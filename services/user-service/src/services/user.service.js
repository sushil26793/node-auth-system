import { UserProfile } from "../models/userProfile.js";
export class UserService {
    async getProfile(userId) {
        return await UserProfile.findOne({ userId });
    }
    async updateProfile(userId, data) {
        delete data.userId;
        delete data.email;
        delete data.isVerified;
        return await UserProfile.findOneAndUpdate({ userId }, { $set: data }, { new: true, runValidators: true });
    }
    async getAllProfiles(limit = 10, page = 1) {
        return await UserProfile.find()
            .skip((page - 1) * limit)
            .limit(limit)
            .sort({ createdAt: -1 });
    }
}
