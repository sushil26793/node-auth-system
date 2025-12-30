import jwt from 'jsonwebtoken';
export const requireAuth = (req, res, next) => {
    const header = req.headers.authorization;
    const internalSecret = req.headers['x-internal-secret'];
    if (internalSecret && (internalSecret === process.env.INTERNAL_SERVICE_SECRET)) {
        return next();
    }
    if (!header?.startsWith("Bearer")) {
        return res.status(401).json({ error: "Unauthorized." });
    }
    try {
        const token = header.split(' ')[1];
        const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        req.user = decoded;
        next();
    }
    catch (error) {
        console.error("Auth Middleware Error:", error);
        res.status(401).json({ error: 'Invalid token' });
    }
};
