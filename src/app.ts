import express, { Express } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
dotenv.config();

import { requestLoggerMiddleware } from './middlewares/requestLogger';
import { connectDB } from './config/database';
import { connectRedis } from './config/redis';
import authRoutes from './routes/auth';
import { errorHandler } from './middlewares/errorHandler';




const app: Express = express();
const PORT = process.env.PORT || 3000;


// CORS configuration

app.use(
  cors({
    origin: (origin, callback) => {
      // allow requests with no origin (mobile apps, curl, Postman web client)
      if (!origin) return callback(null, true);
      return callback(null, true); 
    },
    credentials: true, // allows cookies / auth headers
    methods: ['GET','POST','PUT','DELETE','OPTIONS'],
    allowedHeaders: ['Content-Type','Authorization']
  })
);


// body parser
app.use(express.json({limit:"10mb"}));
app.use(express.urlencoded({limit:"10mb",extended:true}))

app.use(requestLoggerMiddleware);

// auth routes
app.use('/api/auth', authRoutes);

// Health check
app.get('/health', async (req, res) => {
    res.status(200).json({
        status: 'OK',
        timestamp: new Date().toISOString(),
    });
});


app.use((req, res) => {
    res.status(404).json({ success: false, message: "Route not found." })
})


app.use(errorHandler);


export async function startServer(): Promise<void> {
    try {
        await connectDB();
        await connectRedis();
        
        app.listen(PORT, () => {
            console.log(`\n🚀 Server running on http://localhost:${PORT}`);
            console.log(`✓ Environment: ${process.env.NODE_ENV}\n`);
        })
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}


if (require.main === module) {
    startServer();
}