# services/auth-service/Dockerfile
FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --only=production

COPY tsconfig.json ./
COPY src ./src

RUN npm run build

EXPOSE 4001

CMD ["node", "dist/index.js"]
