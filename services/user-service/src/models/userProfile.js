import mongoose, { Schema } from 'mongoose';
const UserProfileSchema = new Schema({
    userId: { type: String, required: true, unique: true, index: true },
    email: { type: String, required: true, index: true },
    firstName: { type: String, trim: true },
    lastName: { type: String, trim: true },
    avatarUrl: { type: String },
    phoneNumber: { type: String },
    bio: { type: String, maxlength: 500 },
    preferences: {
        marketingEmails: { type: Boolean, default: true },
        pushNotifications: { type: Boolean, default: true },
        theme: { type: String, enum: ['light', 'dark'], default: 'light' }
    },
    isVerified: { type: Boolean, default: false }
}, {
    timestamps: true
});
export const UserProfile = mongoose.model('UserProfile', UserProfileSchema);
