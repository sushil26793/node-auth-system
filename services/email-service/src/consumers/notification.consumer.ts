import { kafka } from "../config/kafka";
import { EmailService } from "../services/email.service";
import { logger } from "../utils/logger.util";



const consumer = kafka.consumer({ groupId: 'email-service-group' });
const emailService = new EmailService();


export const startNotificationConsumer = async () => {
    try {

        await consumer.connect();
        await consumer.subscribe({ topic: 'auth.events', fromBeginning: false });
        await consumer.subscribe({ topic: 'user.events', fromBeginning: false });
        logger.info('Email consumer connected');

        await consumer.run({
            eachMessage: async ({ topic, message, partition }) => {
                if (!message.value) return;

                const event = JSON.parse(message.value.toString());
                logger.info(`Received event: ${event.type}`, { topic });

                try {
                    switch (event.type) {
                        case "USER_CREATED":
                            if (event.email && event.verificationToken) {
                                await emailService.sendVerificationEmail(event.email, event.verificationToken);
                            }
                            break;
                        case 'PASSWORD_RESET_REQUESTED':
                            if (event.email && event.resetToken) {
                                await emailService.sendPasswordResetEmail(event.email, event.resetToken)
                            }

                    }
                } catch (err: any) {
                    logger.error('Error processing event', { error: err });

                }
            }
        })

    } catch (error: any) {
        logger.error('Consumer startup failed', { error: error.message });
        process.exit(1);
    }
}