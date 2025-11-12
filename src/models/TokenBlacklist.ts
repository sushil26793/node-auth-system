import mongoose, { Schema } from "mongoose";

interface IBlacklistedToken {
    jti: string;
    userId: string;
    type: 'access' | 'refresh';
    expiresAt: Date;
    createdAt: Date;
}


const blacklistSchema = new Schema<IBlacklistedToken>({
    jti: { type: String, required: true, unique: true, index: true },
    userId: { type: String, required: true, index: true },
    type: { type: String, enum: ["access", "refresh"], required: true },
    expiresAt: { type: Date, required: true }
}, { timestamps: true });


blacklistSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 })

export const TokenBlacklist = mongoose.model<IBlacklistedToken>("TokenBlacklist", blacklistSchema);