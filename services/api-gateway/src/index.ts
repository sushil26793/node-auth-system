import "dotenv/config";
import express from 'express';
import cors from 'cors';
import { globalLimiter } from "./config/rate-limit";
import { logger } from "./utils/logger.util";
import proxyRoutes from './routes/gateway.routes'
const app = express();

app.use(cors({
    origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
    credentials: true
}))

app.use(globalLimiter);

app.get('/healthz', (_req, res) => res.json({ status: 'ok', service: 'api-gateway' }));

app.use("/api/v1", proxyRoutes);

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
    logger.info(`API Gateway running on port ${PORT}`);

})