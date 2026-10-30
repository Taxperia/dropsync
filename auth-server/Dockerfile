FROM node:22-alpine
WORKDIR /app
COPY package.json *.js ./
RUN mkdir -p /data && chown -R node:node /app /data
USER node
ENV DROPSYNC_AUTH_HOST=0.0.0.0 \
    DROPSYNC_AUTH_PORT=8787 \
    DROPSYNC_AUTH_DATA_DIR=/data
EXPOSE 8787
CMD ["node", "server.js"]
