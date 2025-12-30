import { User } from '../models/User.js';
import crypto from 'crypto';
export class AuthService {
    /**
     * Find user by email and handle account locking logic
     */
    async validateUser(email) {
        const user = await User.findOne({ email });
        if (!user) {
            throw new Error('Invalid credentials');
        }
        if (user.isLocked()) {
            throw new Error('Account is temporarily locked');
        }
        return user;
    }
    /**
     * Handle password verification and failed attempt tracking
     */
    async verifyPassword(user, password) {
        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            user.failedLoginAttempts += 1;
            if (user.failedLoginAttempts >= 5) {
                user.lockUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 mins
            }
            await user.save();
            return false;
        }
        // Reset on success
        if (user.failedLoginAttempts > 0) {
            user.failedLoginAttempts = 0;
            user.lockUntil = undefined;
            await user.save();
        }
        return true;
    }
    /**
     * Create new user
     */
    async createUser(email, password) {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            throw new Error('Email already registered');
        }
        const verificationToken = crypto.randomBytes(32).toString('hex');
        const user = await User.create({
            email,
            password,
            emailVerificationToken: verificationToken,
            role: 'user'
        });
        return { user, verificationToken };
    }
}
