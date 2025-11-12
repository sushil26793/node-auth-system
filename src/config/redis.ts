import { createClient, RedisClientType } from "redis";

let redisClient: RedisClientType | null = null;


export const connectRedis = async (): Promise<RedisClientType> => {
    try {
        const client: RedisClientType = createClient({
            url: process.env.REDIS_URL
        })
        client.on("error", (error) => {
            console.error("Redis Client Error:", error);

        });
        client.on('connect', () => {
            console.log('✓ Redis connected successfully');
        });

        await client.connect();
        redisClient = client;
        return client;
    } catch (error) {
        console.error("✗ Redis connection failed:", error);
        throw error;
    }
}


export const getRedisClient = (): RedisClientType => {
    if (!redisClient) throw new Error("Redis client not initialized.");
    return redisClient;
}


export const disconnectRedis = async (): Promise<void> => {
    if (redisClient) {
        await redisClient.destroy();
        console.log("✓ Redis disconnected");
    }
}