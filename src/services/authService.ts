import { User } from "../models/User";
import { AppError } from "../types";
import { tokenService } from "./tokenService";


export class AuthService {

    async register(email: string, password: string): Promise<any> {
        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) throw new AppError(400, "Email already registered.");
        if (!/(?=.*[a-z])/.test(password)) throw new AppError(400, "Password must contain lowercase letters.");
        if (!/(?=.*[A-Z])/.test(password)) throw new AppError(400, "Password must contain upercase letters.");
        if (!/(?=.*\d)/.test(password)) throw new AppError(400, "Password must contain numbers.");
        const user = new User({
            email: email.toLowerCase(),
            password,
            tokenVersion: 0,
            refreshTokens: []
        });
        await user.save();
        const tokens = await tokenService.generateTokenPair(user._id.toString(), user.email, user.tokenVersion);
        return { user: user.toJSON(), ...tokens };

    }


    async login(email: string, password: string): Promise<any> {
        const user = await User.findOne({ email: email.toLowerCase() }).select("+password");
        if (!user) {
            throw new AppError(401, 'Invalid credentials');
        }

        const isPasswordValid = await user.comparePassword(password);
        if (!isPasswordValid) {
            throw new AppError(401, "Invalid credentials.")
        }

        if (!user.isActive) {
            throw new AppError(403, "user account is deactivated.");
        }

        const tokens = await tokenService.generateTokenPair(user._id.toString(), user.email, user.tokenVersion);
        return {
            user: user.toJSON(),
            ...tokens
        }
    }


    async logout(userId: string): Promise<void> {
        await tokenService.revokeAllUserTokens(userId);
    }


    async changePassword(userId: string, oldPassword: string, newPassword: string): Promise<void> {
        const user = await User.findById(userId).select("+password");
        if (!user) {
            throw new AppError(404, "User not found.");
        }

        const isPasswordMatch = await user.comparePassword(oldPassword);
        if (!isPasswordMatch) {
            throw new AppError(401, "Current password is incorrect.")
        }
        user.password = newPassword;
        await user.save();
        await tokenService.revokeAllUserTokens(userId);
    };

    async getCurrentUser(userId: string): Promise<any> {
        const user = await User.findById(userId).select("-refreshTokens")
        if (!user) {
            throw new AppError(404, "User not found.")
        }
        if (!user.isActive) {
            throw new AppError(403, "User account is diactivated.")
        }
        return user;
    }
}


export const authService = new AuthService();
