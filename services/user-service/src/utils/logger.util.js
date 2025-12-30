// services/user-service/src/utils/logger.util.ts
export const logger = {
    info: (message, meta) => {
        console.log(JSON.stringify({
            level: 'info',
            timestamp: new Date().toISOString(),
            service: 'user-service',
            message,
            ...meta
        }));
    },
    error: (message, meta) => {
        console.error(JSON.stringify({
            level: 'error',
            timestamp: new Date().toISOString(),
            service: 'user-service',
            message,
            ...meta
        }));
    },
    warn: (message, meta) => {
        console.warn(JSON.stringify({
            level: 'warn',
            timestamp: new Date().toISOString(),
            service: 'user-service',
            message,
            ...meta
        }));
    }
};
