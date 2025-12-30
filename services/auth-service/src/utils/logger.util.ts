


export const logger = {
    info(message: string, meta?: any) {
        console.log(JSON.stringify({ level: "info", message, ...meta }))
    },
    warn(message: string, meta?: any) {
        console.warn(JSON.stringify({ level: "warn", message, ...meta }))
    },
    error(message: string, meta?: any) {
        console.error(JSON.stringify({ level: 'error', message, ...meta }));
    }
}