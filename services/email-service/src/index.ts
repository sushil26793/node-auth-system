import 'dotenv/config';
import { startNotificationConsumer } from './consumers/notification.consumer';
import { logger } from './utils/logger.util';








const start = async () => {
    logger.info('Starting Email Service...');
    await startNotificationConsumer();

}

start();


process.on('unhandledRejection', (err) => {
    logger.error('Unhandled Rejection', { error: err });
    process.exit(1);
});