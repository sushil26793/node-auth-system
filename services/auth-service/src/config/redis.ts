import { createClient } from "redis";
import { logger } from "../utils/logger.util.js";

const client = createClient({ url: process.env.REDIS_URL || 'redis://redis:6379' });


client.on('error', (err) => logger.error('Redis error', { error: err.message }))
client.on('connect', () => logger.info('Redis connected'));
client.connect().catch((err) =>
    logger.error('Redis connect failed', { error: err.message })
);


export default {
    async get(key: string) {
        return client.get(key);
    },
    async setex(key: string, ttlSeconds: number, value: string) {
        await client.setEx(key, ttlSeconds, value);
    },
    async del(key: string) {
        await client.del(key);
    }
}