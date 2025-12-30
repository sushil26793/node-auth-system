// services/user-service/src/config/database.ts
import mongoose from 'mongoose';
import { logger } from '../utils/logger.util.js';

export const connectDatabase = async () => {
  try {
    const uri = process.env.MONGO_URI || 'mongodb://localhost:27017/userdb';
    await mongoose.connect(uri);
    logger.info('Connected to User Database (MongoDB)');
  } catch (error: any) {
    logger.error('MongoDB connection error', { error: error.message });
    process.exit(1);
  }
};
