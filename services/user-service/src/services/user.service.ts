import { UserProfile, IUserProfile } from "../models/userProfile.js";


export class UserService {
    async getProfile(userId: string): Promise<IUserProfile | null> {
        return await UserProfile.findOne({ userId })
    }

    async updateProfile(userId: string, data: Partial<IUserProfile>): Promise<IUserProfile | null> {
        delete data.userId;
        delete data.email;
        delete data.isVerified;
        return await UserProfile.findOneAndUpdate(
            { userId },
            { $set: data },
            { new: true, runValidators: true }
        )
    }

    async getAllProfiles(limit: number = 10, page: number = 1): Promise<IUserProfile[]> {
        return await UserProfile.find()
            .skip((page - 1) * limit)
            .limit(limit)
            .sort({ createdAt: -1 });
    }

}

