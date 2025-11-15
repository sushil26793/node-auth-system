import express, { Express } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';

dotenv.config();

import { requestLoggerMiddleware } from './middlewares/requestLogger';
import { connectDB, disconnectDB } from './config/database';
import { connectRedis, disconnectRedis } from './config/redis';
import authRoutes from './routes/auth';
import { errorHandler } from './middlewares/errorHandler';
import { apiLimiter } from './middlewares/rateLImit';

const app: Express = express();
const PORT = process.env.PORT || 3000;

/**
 * 1. SECURITY HEADERS - FIRST (Helmet)
 * Protects against common vulnerabilities by setting HTTP headers
 */
app.use(helmet());

/**
 * 2. CORS CONFIGURATION
 * Allow cross-origin requests from trusted sources
 */
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (mobile apps, curl, Postman)
      if (!origin) return callback(null, true);
      
      // In production, whitelist specific origins
      const allowedOrigins = process.env.FRONTEND_URL?.split(',') || ['http://localhost:3000'];
      
      if (process.env.NODE_ENV === 'production') {
        if (allowedOrigins.includes(origin)) {
          return callback(null, true);
        } else {
          return callback(new Error('Not allowed by CORS'));
        }
      }
      
      // Allow all in development
      return callback(null, true);
    },
    credentials: true, // allows cookies / auth headers
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

/**
 * 3. BODY PARSER - MUST BE BEFORE ROUTES
 * Parse JSON and URL-encoded request bodies
 */
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

/**
 * 4. REQUEST LOGGER
 * Log all incoming requests for debugging
 */
app.use(requestLoggerMiddleware);

/**
 * 5. RATE LIMITING
 * Protect against brute-force attacks
 */
app.use('/api', apiLimiter);

/**
 * 6. ROUTES
 * Define application routes
 */
app.use('/api/auth', authRoutes);

/**
 * 7. HEALTH CHECK
 * Simple endpoint to verify server is running
 */
app.get('/health', async (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

/**
 * 8. 404 HANDLER
 * Catch-all for undefined routes
 */
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found',
    path: req.path,
  });
});

/**
 * 9. ERROR HANDLER - MUST BE LAST
 * Global error handling middleware
 */
app.use(errorHandler);

/**
 * SERVER STARTUP
 */
export async function startServer(): Promise<void> {
  try {
    // Connect to databases
    await connectDB();
    await connectRedis();

    // Start server
    app.listen(PORT, () => {
      console.log(`\n🚀 Server running on http://localhost:${PORT}`);
      console.log(`✓ Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`✓ MongoDB: Connected`);
      console.log(`✓ Redis: Connected\n`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

/**
 * GRACEFUL SHUTDOWN
 */
async function gracefulShutdown(signal: string): Promise<void> {
  console.log(`\n${signal} received. Shutting down gracefully...`);
  
  try {
    await disconnectDB();
    await disconnectRedis();
    console.log('✓ All connections closed');
    process.exit(0);
  } catch (error) {
    console.error('Error during shutdown:', error);
    process.exit(1);
  }
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Start if run directly
if (require.main === module) {
  startServer();
}

export default app;