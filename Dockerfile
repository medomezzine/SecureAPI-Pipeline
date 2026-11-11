FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
# Refresh npm's bundled packages; old CLI dependencies can carry image CVEs.
RUN npm install --global npm@11
RUN npm install --omit=dev
COPY src ./src
COPY public ./public
RUN mkdir -p /app/data && chown -R node:node /app
USER node
ENV NODE_ENV=production PORT=3000
EXPOSE 3000
CMD ["npm", "start"]
