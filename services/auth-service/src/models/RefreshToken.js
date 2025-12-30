// services/auth-service/src/models/RefreshToken.ts
import mongoose, { Schema } from 'mongoose';
const RefreshTokenSchema = new Schema({
    userId: { type: String, required: true, index: true },
    tokenId: { type: String, required: true, unique: true, index: true },
    hashedToken: { type: String, required: true },
    deviceId: { type: String, required: true, index: true },
    ipAddress: { type: String, required: true },
    userAgent: { type: String, required: true },
    expiresAt: { type: Date, required: true, index: true },
    isRevoked: { type: Boolean, default: false, index: true },
    isUsed: { type: Boolean, default: false, index: true },
    usedAt: { type: Date },
    rotatedTo: { type: String },
    rotationCount: { type: Number, default: 0 },
    revokedAt: { type: Date },
    createdAt: { type: Date, default: Date.now }
});
// Compound index for efficient device queries
RefreshTokenSchema.index({ userId: 1, deviceId: 1 });
RefreshTokenSchema.index({ userId: 1, isRevoked: 1 });
export const RefreshToken = mongoose.model('RefreshToken', RefreshTokenSchema);
