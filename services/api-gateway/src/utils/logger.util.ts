

export const logger = {
    info: (message: string, meta?: any) => {
        console.log(JSON.stringify({ level: 'info', service: 'api-gateway', message, ...meta }));
    },
    error: (message: string, meta?: any) => {
        console.error(JSON.stringify({ level: 'error', service: 'api-gateway', message, ...meta }));
    }
};
