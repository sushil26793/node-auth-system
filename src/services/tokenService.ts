import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { getRedisClient } from '../config/redis';
import { TokenBlacklist } from '../models/TokenBlacklist';
import { User } from '../models/User';
import { JWTPayload, TokenPair, AppError, RedisTokenData } from '../types';

export class TokenService {
    private readonly accessSecret = process.env.JWT_ACCESS_SECRET!;
    private readonly refreshSecret = process.env.JWT_REFRESH_SECRET!;
    private readonly accessExpiry = process.env.ACCESS_TOKEN_EXPIRY || '15m';
    private readonly refreshExpiry = process.env.REFRESH_TOKEN_EXPIRY || '7d';

    /**
     * Generate access and refresh token pair
     */
    async generateTokenPair(
        userId: string,
        email: string,
        tokenVersion: number
    ): Promise<TokenPair> {
        const jti = uuidv4();

        const accessPayload: JWTPayload = {
            userId,
            email,
            tokenVersion,
            type: 'access' as any,
            jti: uuidv4(),
        };

        const refreshPayload: JWTPayload = {
            userId,
            email,
            tokenVersion,
            type: 'refresh' as any,
            jti,
        };

        const accessToken = jwt.sign(accessPayload, this.accessSecret, {
            expiresIn: this.accessExpiry,
        });

        const refreshToken = jwt.sign(refreshPayload, this.refreshSecret, {
            expiresIn: this.refreshExpiry,
        });

        // Store refresh token JTI in Redis for faster blacklist lookups
        const redis = getRedisClient();
        const refreshExpirySeconds = this.parseExpiry(this.refreshExpiry);
        await redis.setEx(
            `refresh_token:${jti}`,
            refreshExpirySeconds,
            userId
        );

        // Store in MongoDB for persistence
        await User.findByIdAndUpdate(userId, {
            $addToSet: { refreshTokens: jti },
        });

        return {
            accessToken,
            refreshToken,
            expiresIn: this.accessExpiry,
        };
    }

    /**
     * Verify and decode JWT token
     */
    verifyAccessToken(token: string): JWTPayload {
        try {
            const decoded = jwt.verify(token, this.accessSecret) as JWTPayload;
            return decoded;
        } catch (error) {
            if (error instanceof jwt.TokenExpiredError) {
                throw new AppError(401, 'Access token has expired');
            }
            throw new AppError(401, 'Invalid access token');
        }
    }

    /**
     * Refresh access token using refresh token
     */
    async refreshAccessToken(refreshToken: string): Promise<TokenPair> {
        try {
            const decoded = jwt.verify(
                refreshToken,
                this.refreshSecret
            ) as JWTPayload;

            // Check if refresh token is blacklisted
            const isBlacklisted = await this.isTokenBlacklisted(decoded.jti!);
            if (isBlacklisted) {
                throw new AppError(401, 'Refresh token has been revoked');
            }

            // Verify token version matches
            const user = await User.findById(decoded.userId);
            if (!user) {
                throw new AppError(404, 'User not found');
            }

            if (user.tokenVersion !== decoded.tokenVersion) {
                throw new AppError(
                    401,
                    'Token version mismatch - user tokens have been invalidated'
                );
            }

            // Generate new token pair
            const newTokens = await this.generateTokenPair(
                user._id.toString(),
                user.email,
                user.tokenVersion
            );

            // Blacklist old refresh token
            const expiryDate = new Date((decoded.exp || 0) * 1000);
            await this.blacklistToken(
                decoded.jti!,
                decoded.userId,
                'refresh',
                expiryDate
            );

            return newTokens;
        } catch (error) {
            if (error instanceof AppError) throw error;
            if (error instanceof jwt.TokenExpiredError) {
                throw new AppError(401, 'Refresh token has expired');
            }
            throw new AppError(401, 'Invalid refresh token');
        }
    }

    /**
     * Blacklist a token
     */
    async blacklistToken(
        jti: string,
        userId: string,
        type: 'access' | 'refresh',
        expiresAt: Date
    ): Promise<void> {
        const redis = getRedisClient();

        // Store in Redis for fast lookups
        const key = `blacklist:${jti}`;
        const ttl = Math.floor((expiresAt.getTime() - Date.now()) / 1000);

        if (ttl > 0) {
            await redis.setEx(key, ttl, userId);
        }

        // Store in MongoDB for persistence
        await TokenBlacklist.create({
            jti,
            userId,
            type,
            expiresAt,
        });
    }

    /**
     * Check if token is blacklisted
     */
    async isTokenBlacklisted(jti: string): Promise<boolean> {
        const redis = getRedisClient();
        const result = await redis.get(`blacklist:${jti}`);
        return result !== null;
    }

    /**
     * Revoke all user tokens (called on password change, logout, etc.)
     */
    async revokeAllUserTokens(userId: string): Promise<void> {
        const user = await User.findById(userId);
        if (!user) {
            throw new AppError(404, 'User not found');
        }

        // Increment token version to invalidate all existing tokens
        await User.findByIdAndUpdate(userId, {
            $inc: { tokenVersion: 1 },
            $set: { refreshTokens: [] },
        });

        // Blacklist all existing refresh tokens
        const redis = getRedisClient();
        for (const jti of user.refreshTokens) {
            await redis.del(`refresh_token:${jti}`);
        }
    }

    /**
     * Parse expiry string (e.g., "7d", "15m") to seconds
     */
    private parseExpiry(expiry: string): number {
        const match = expiry.match(/^(\d+)([smhd])$/);
        if (!match) throw new Error('Invalid expiry format');

        const [, value, unit] = match;
        const num = parseInt(value);

        const units: Record<string, number> = {
            s: 1,
            m: 60,
            h: 3600,
            d: 86400,
        };

        return num * (units[unit] || 1);
    }

    /**
     * Detect suspicious token usage
     */
    async detectTokenAnomalies(
        userId: string,
        token: string
    ): Promise<boolean> {
        const redis = getRedisClient();
        const decoded = jwt.decode(token) as JWTPayload;

        // Check if same token is being used from multiple IPs (can be extended)
        const key = `token_usage:${userId}:${decoded.jti || decoded.email}`;
        const usage = await redis.incr(key);

        if (usage === 1) {
            await redis.expire(key, 3600); // 1 hour expiry
        }

        // Anomaly if token used more than threshold in short time
        return usage > 10;
    }
}

export const tokenService = new TokenService();
