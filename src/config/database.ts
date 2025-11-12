import mongoose from "mongoose";


export const connectDB = async (): Promise<void> => {
    try {
        const uri = process.env.MONGODB_URI || 'mongodb://localhost:27017/auth_system';
        await mongoose.connect(uri)
        console.log('✓ MongoDB connected successfully');
    } catch (error) {
        console.error('✗ MongoDB connection failed:', error);
        process.exit(1);
    }
}

export const disconnectDB = async (): Promise<void> => {
    try {
        await mongoose.disconnect();
        console.log('✓ MongoDB disconnected');
    } catch (error) {
        console.error('✗ MongoDB disconnection failed:', error);
    }
}