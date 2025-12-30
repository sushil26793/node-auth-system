import { Kafka } from 'kafkajs';
import { UserProfile } from '../models/userProfile.js';
import { logger } from '../utils/logger.util.js';
import { kafkaConfig } from '../config/kafka.js';
const kafka = new Kafka(kafkaConfig);
const consumer = kafka.consumer({ groupId: 'user-service-group' });
export const startAuthConsumer = async () => {
    try {
        await consumer.connect();
        await consumer.subscribe({ topic: 'user.events', fromBeginning: false });
        logger.info('Auth consumer connected and subscribed');
        await consumer.run({
            eachMessage: async ({ topic, partition, message }) => {
                const prefix = `${topic}[${partition}|${message.offset}] / ${message.timestamp}`;
                if (!message.value)
                    return;
                const event = JSON.parse(message.value.toString());
                logger.info(`- ${prefix} ${event.type}`);
                try {
                    await handleAuthEvent(event);
                }
                catch (error) {
                    logger.error(`Error handling event ${event.type}`, { error: error.message });
                    // In production: push to dead-letter queue (DLQ) here
                }
            },
        });
    }
    catch (error) {
        logger.error('Auth consumer failed', { error: error.message });
    }
};
async function handleAuthEvent(event) {
    switch (event.type) {
        case 'USER_CREATED':
            // Idempotency check: update if exists, create if not
            await UserProfile.findOneAndUpdate({ userId: event.userId }, {
                userId: event.userId,
                email: event.email,
                isVerified: false,
                $setOnInsert: {
                    preferences: { theme: 'light', marketingEmails: true, pushNotifications: true }
                }
            }, { upsert: true, new: true });
            logger.info('Profile created/synced for user', { userId: event.userId });
            break;
        case 'USER_VERIFIED': // Assuming Auth service emits this later
            await UserProfile.updateOne({ userId: event.userId }, { isVerified: true });
            break;
        case 'ALL_TOKENS_REVOKED': // Example of reacting to security events
            logger.info('User security reset received', { userId: event.userId });
            // Can clear local caches or sensitive data if needed
            break;
    }
}
