
export interface JWTPayload {
    userId: string;
    email: string;
    tokenVersion: number;
    type:"access"|"refresh";
    jti?:string;
    iat?: number;
    exp?: number;
}

export interface TokenPair {
    accessToken: string;
    refreshToken: string;
    expiresIn: string;
}

export interface AuthRequest {
    email: string;
    password: string;
}

export interface UserDocument {
    _id: string;
    email: string;
    password: string;
    tokenVersion: number;
    refreshTokens: string[];
    isActive: boolean;
    createdAt: Date;
    updatedAt: Date;
    comparePassword(password: string): Promise<boolean>;
}

export interface RedisTokenData {
    userId: string;
    jti: string;
    exp: number;
    type: 'access' | 'refresh';
}

export class AppError extends Error {
    constructor(
        public statusCode: number,
        message: string
    ) {
        super(message);
        Object.setPrototypeOf(this, AppError.prototype);
    }
}
