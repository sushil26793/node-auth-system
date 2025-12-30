import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { connectDatabase } from './config/database.js';
import { startAuthConsumer } from './consumers/auth.consumer.js';
import authRoutes from "./routes/user.route.js";
export const app = express();
app.use(express.json());
app.use(cors());
app.use('/users', authRoutes);
app.get('/healthz', (_req, res) => res.json({ status: 'ok', service: 'user-service' }));
const PORT = process.env.PORT || "4002";
async function startServer() {
    try {
        await connectDatabase();
        await startAuthConsumer();
        app.listen(PORT, () => {
            console.log(`User Service running on port ${PORT}`);
        });
    }
    catch (error) {
        console.log(error);
        process.exit(1);
    }
}
import { fileURLToPath } from 'url';
if (process.argv[1] === fileURLToPath(import.meta.url)) {
    startServer();
}
