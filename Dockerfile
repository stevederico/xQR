FROM node:22-slim

WORKDIR /app

# Install dependencies for Playwright WebKit
RUN apt-get update && apt-get install -y \
    fonts-liberation \
    fonts-noto-core \
    fonts-noto-color-emoji \
    fonts-freefont-ttf \
    fonts-dejavu-core \
    fontconfig \
    ca-certificates \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcups2 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libgtk-4-1 \
    libgraphene-1.0-0 \
    libatomic1 \
    libevent-2.1-7 \
    libwebpdemux2 \
    libavif15 \
    libnspr4 \
    libnss3 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libwoff1 \
    libharfbuzz-icu0 \
    libenchant-2-2 \
    libsecret-1-0 \
    libhyphen0 \
    libmanette-0.2-0 \
    libgles2 \
    gstreamer1.0-libav \
    gstreamer1.0-plugins-bad \
    xdg-utils \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Copy package files
COPY package*.json ./
COPY backend/package*.json ./backend/

# Install dependencies (includes devDeps for build)
RUN npm install

# Install Playwright WebKit browser only
RUN npx playwright install webkit

# Copy source
COPY . .

# Build frontend
RUN npm run build

# Set production mode after build
ENV NODE_ENV production
ENV PORT 8080

# Expose port
EXPOSE 8080

# Start server with experimental SQLite
CMD ["node", "--experimental-sqlite", "backend/server.js"]
