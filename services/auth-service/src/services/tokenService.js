import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { RefreshToken } from '../models/RefreshToken.js';
import { AuditLog } from '../models/AuditLog.js';
import RedisClient from '../config/redis.js';
import { KafkaProducer } from './kafka-producer.service.js';
import { logger } from '../utils/logger.util.js';
/**
 * TokenService handles JWT generation, refresh token rotation,
 * reuse detection, and token revocation with Redis caching
 */
export class TokenService {
    constructor() {
        this.accessTokenExpiry = '15m';
        this.refreshTokenExpiry = '7d';
        this.accessTokenSecret = process.env.ACCESS_TOKEN_SECRET;
        this.refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET;
        this.kafkaProducer = new KafkaProducer();
    }
    /**
     * Generate access token with user payload
     * Short-lived token (15 minutes) for API access
     */
    generateAccessToken(userId, role, deviceId) {
        return jwt.sign({
            userId,
            role,
            deviceId,
            type: 'access'
        }, this.accessTokenSecret, {
            expiresIn: '15m',
            issuer: 'auth-service',
            audience: 'api-gateway'
        });
    }
    /**
     * Generate refresh token with rotation tracking
     * Hashed before storage for security
     */
    async generateRefreshToken(userId, deviceId, ipAddress, userAgent) {
        const tokenId = crypto.randomBytes(32).toString('hex');
        const token = jwt.sign({
            userId,
            deviceId,
            tokenId,
            type: 'refresh'
        }, this.refreshTokenSecret, {
            expiresIn: '7d',
            issuer: 'auth-service'
        });
        // Hash token before storing (defense in depth)
        const hashedToken = this.hashToken(token);
        // Store refresh token with metadata for rotation tracking
        await RefreshToken.create({
            userId,
            tokenId,
            hashedToken,
            deviceId,
            ipAddress,
            userAgent,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
            isRevoked: false,
            isUsed: false,
            rotationCount: 0
        });
        // Cache token metadata in Redis for fast lookup
        await RedisClient.setex(`refresh:${tokenId}`, 7 * 24 * 60 * 60, JSON.stringify({ userId, deviceId, hashedToken }));
        // Log token creation
        await this.auditLog(userId, 'REFRESH_TOKEN_CREATED', { deviceId, tokenId });
        return { token, tokenId };
    }
    /**
     * Rotate refresh token - critical security mechanism
     * Implements automatic reuse detection and token family revocation
     */
    async rotateRefreshToken(oldToken, ipAddress, userAgent) {
        try {
            // Verify and decode old token
            const decoded = jwt.verify(oldToken, this.refreshTokenSecret);
            const { userId, deviceId, tokenId } = decoded;
            // Hash the incoming token for comparison
            const hashedOldToken = this.hashToken(oldToken);
            const storedToken = await RefreshToken.findOne({ tokenId, userId });
            if (!storedToken) {
                logger.warn('Token not found', { tokenId, userId });
                return null;
            }
            /**
             * REUSE DETECTION: Critical security check
             * If token is already used, it indicates potential token theft
             * Revoke entire token family for this device
             */
            if (storedToken.isUsed) {
                logger.error('SECURITY: Refresh token reuse detected!', {
                    userId,
                    deviceId,
                    tokenId,
                    ipAddress
                });
                // Revoke all tokens for this device (token family)
                await this.revokeTokenFamily(userId, deviceId);
                // Publish security event to Kafka
                await this.kafkaProducer.publishEvent('auth.events', {
                    type: 'TOKEN_REUSE_DETECTED',
                    userId,
                    deviceId,
                    tokenId,
                    ipAddress,
                    timestamp: new Date()
                });
                // Audit log
                await this.auditLog(userId, 'TOKEN_REUSE_DETECTED', {
                    deviceId,
                    tokenId,
                    ipAddress,
                    action: 'FAMILY_REVOKED'
                });
                return null;
            }
            // Verify token hash matches stored hash
            if (storedToken.hashedToken !== hashedOldToken) {
                logger.warn('Token hash mismatch', { tokenId });
                return null;
            }
            // Check if token is revoked
            if (storedToken.isRevoked) {
                logger.warn('Token is revoked', { tokenId });
                return null;
            }
            // Mark old token as used (one-time use only)
            storedToken.isUsed = true;
            storedToken.usedAt = new Date();
            storedToken.rotationCount += 1;
            await storedToken.save();
            // Invalidate old token in Redis
            await RedisClient.del(`refresh:${tokenId}`);
            // Generate new token pair (rotation)
            const newAccessToken = this.generateAccessToken(userId, 'user', deviceId);
            const { token: newRefreshToken, tokenId: newTokenId } = await this.generateRefreshToken(userId, deviceId, ipAddress, userAgent);
            // Link tokens in rotation chain for tracking
            await RefreshToken.updateOne({ tokenId }, { $set: { rotatedTo: newTokenId } });
            // Publish rotation event to Kafka
            await this.kafkaProducer.publishEvent('auth.events', {
                type: 'TOKEN_ROTATED',
                userId,
                deviceId,
                oldTokenId: tokenId,
                newTokenId,
                rotationCount: storedToken.rotationCount,
                timestamp: new Date()
            });
            // Audit log
            await this.auditLog(userId, 'TOKEN_ROTATED', {
                deviceId,
                oldTokenId: tokenId,
                newTokenId
            });
            logger.info('Token rotated successfully', { userId, deviceId, rotationCount: storedToken.rotationCount });
            return {
                accessToken: newAccessToken,
                refreshToken: newRefreshToken,
                deviceId
            };
        }
        catch (error) {
            if (error.name === 'TokenExpiredError') {
                logger.warn('Refresh token expired', { error: error.message });
            }
            else {
                logger.error('Token rotation failed', { error: error.message });
            }
            return null;
        }
    }
    /**
     * Revoke all refresh tokens for a user device (token family)
     * Used when reuse is detected or user logs out from a device
     */
    async revokeTokenFamily(userId, deviceId) {
        // Mark all tokens for this device as revoked
        await RefreshToken.updateMany({ userId, deviceId, isRevoked: false }, { $set: { isRevoked: true, revokedAt: new Date() } });
        // Remove from Redis cache
        const tokens = await RefreshToken.find({ userId, deviceId });
        for (const token of tokens) {
            await RedisClient.del(`refresh:${token.tokenId}`);
        }
        // Publish event
        await this.kafkaProducer.publishEvent('auth.events', {
            type: 'TOKEN_FAMILY_REVOKED',
            userId,
            deviceId,
            timestamp: new Date()
        });
        logger.info('Token family revoked', { userId, deviceId });
    }
    /**
     * Revoke all tokens for a user (all devices)
     * Used for password reset or account compromise
     */
    async revokeAllUserTokens(userId) {
        await RefreshToken.updateMany({ userId, isRevoked: false }, { $set: { isRevoked: true, revokedAt: new Date() } });
        // Clear Redis cache for all user tokens
        const tokens = await RefreshToken.find({ userId });
        for (const token of tokens) {
            await RedisClient.del(`refresh:${token.tokenId}`);
        }
        await this.kafkaProducer.publishEvent('auth.events', {
            type: 'ALL_TOKENS_REVOKED',
            userId,
            timestamp: new Date()
        });
        logger.info('All user tokens revoked', { userId });
    }
    /**
     * Verify access token
     */
    verifyAccessToken(token) {
        try {
            return jwt.verify(token, this.accessTokenSecret);
        }
        catch (error) {
            return null;
        }
    }
    /**
     * Hash token using SHA-256 for storage
     */
    hashToken(token) {
        return crypto.createHash('sha256').update(token).digest('hex');
    }
    /**
     * Audit logging for security events
     */
    async auditLog(userId, action, metadata) {
        await AuditLog.create({
            userId,
            action,
            metadata,
            timestamp: new Date()
        });
    }
    /**
     * Token eviction strategy - cleanup expired tokens
     * Run as a scheduled job (cron) to prevent database bloat
     */
    async cleanupExpiredTokens() {
        const deleted = await RefreshToken.deleteMany({
            expiresAt: { $lt: new Date() }
        });
        logger.info('Expired tokens cleaned up', { count: deleted.deletedCount });
    }
}
