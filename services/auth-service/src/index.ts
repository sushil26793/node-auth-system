
import 'dotenv/config.js';
import express from 'express';
import { connectDatabase } from "./config/database.js";
import { logger } from "./utils/logger.util.js";
import { kafkaProducer } from "./services/kafka-producer.service.js";
import cors from "cors";
import authRoutes from "./routes/auth.route.js";
import cookieParser from "cookie-parser";
export const app = express();

// Security & parsing
app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: process.env.CORS_ORIGIN?.split(',') || ['http://localhost:3000'],
    credentials: true
}))

app.get('/healthz', (_req, res) => {
    res.json({ status: 'ok', service: "auth-service" });
})


app.use('/auth', authRoutes);


async function startServer() {
    const PORT = process.env.PORT || 4001;
    try {
        await connectDatabase();
        logger.info('MongoDB connected');
        // kafka 
        await kafkaProducer.connect();
        logger.info('Kafka producer connected');
        app.listen(PORT, () => {
            console.log(`Auth service is running on port ${PORT}`);
        });
    } catch (error: any) {
        console.log("Failed to start server", error);
        logger.error("Failed to start server", { error: error.message })
        process.exit(1);
    }
}




import { fileURLToPath } from 'url';

if (process.argv[1] === fileURLToPath(import.meta.url) && process.env.NODE_ENV !== 'test') {
    startServer();
}
