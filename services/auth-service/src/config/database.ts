import mongoose from "mongoose";
import { logger } from "../utils/logger.util.js";



export const connectDatabase= async ()=>{
    await mongoose.connect(process.env.MONGO_URI as string);
    logger.info('Auth service database connected')
    
}