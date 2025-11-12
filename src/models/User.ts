import mongoose, { Schema } from "mongoose";
import bcrypt from 'bcryptjs';
import { UserDocument } from "../types";


const userSchema = new Schema<UserDocument>({
    email: { type: String, required: [true, "Email is required."], unique: true, lowercase: true, match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Invalid email format'], },
    password: { type: String, required: [true, "Password is required."], minlength: 6, select: false, },
    tokenVersion: { type: Number, default: 0 },
    refreshTokens: [{ type: String, description: 'Increment to invalidate all refresh tokens' }],
    isActive: { type: Boolean, default: true },
}, { timestamps: true });

// Hash password before saving
userSchema.pre("save", async function (next) {
    if (!this.isModified('password')) return next();
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error as Error)
    }
})

// password comparision

userSchema.methods.comparePassword = async function (candidatPassword: string): Promise<boolean> {
    return bcrypt.compare(candidatPassword, this.password);
}


// Hide sensitive info 

userSchema.methods.toJSON = function () {
    const obj = this.toObject();
    delete obj.password;
    delete obj.refreshTokens;
    return obj;
}


export const User = mongoose.model<UserDocument>('User', userSchema)