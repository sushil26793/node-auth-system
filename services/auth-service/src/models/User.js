import mongoose, { Schema } from 'mongoose';
import bcrypt from 'bcryptjs';
const UserSchema = new Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        index: true
    },
    password: { type: String, required: true },
    role: {
        type: String,
        enum: ['user', 'admin', 'moderator'],
        default: 'user',
        index: true
    },
    isEmailVerified: { type: Boolean, default: false },
    emailVerificationToken: { type: String },
    passwordResetToken: { type: String, index: true },
    passwordResetExpires: { type: Date },
    failedLoginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date }
}, {
    timestamps: true
});
// Hash password before saving
UserSchema.pre('save', async function () {
    if (!this.isModified('password'))
        return;
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
});
// Compare password method
UserSchema.methods.comparePassword = async function (candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
};
// Check if account is locked
UserSchema.methods.isLocked = function () {
    return !!(this.lockUntil && this.lockUntil > new Date());
};
export const User = mongoose.model('User', UserSchema);
