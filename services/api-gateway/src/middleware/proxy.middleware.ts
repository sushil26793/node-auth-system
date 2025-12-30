import proxy from "express-http-proxy";
import { Request } from "express";



const AUTH_SERVICE_URL = process.env.AUTH_SERVICE_URL || 'http://127.0.0.1:4001';
const USER_SERVICE_URL = process.env.USER_SERVICE_URL || 'http://127.0.0.1:4002';

console.log('Gateway Config:', { AUTH_SERVICE_URL, USER_SERVICE_URL });

export const authProxy = proxy(AUTH_SERVICE_URL, {
    proxyReqPathResolver: (req: Request) => {
        return `/auth${req.url}`
    },
    userResDecorator: (proxyRes, proxyResData, userReq, userRes) => {
        return proxyResData;
    }
})


export const userProxy = proxy(USER_SERVICE_URL, {
    proxyReqPathResolver: (req: Request) => {
        return `/users${req.url}`;
    }
})
