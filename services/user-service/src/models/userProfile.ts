import mongoose, { Document, Schema } from 'mongoose';

export interface IUserProfile extends Document {
  userId: string; // Reference to Auth Service User ID
  email: string;  // Denormalized for easy access
  firstName?: string;
  lastName?: string;
  avatarUrl?: string;
  phoneNumber?: string;
  bio?: string;
  preferences: {
    marketingEmails: boolean;
    pushNotifications: boolean;
    theme: 'light' | 'dark';
  };
  isVerified: boolean; // Synced from Auth events
  createdAt: Date;
  updatedAt: Date;
}

const UserProfileSchema = new Schema<IUserProfile>({
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

export const UserProfile = mongoose.model<IUserProfile>('UserProfile', UserProfileSchema);
