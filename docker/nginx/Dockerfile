FROM nginx:latest

RUN apk add --no-cache --virtual openssl \
    && mkdir -p /app/public

COPY conf/app.conf /etc/nginx/conf.d/default.conf
COPY --from=go-build bin/redirector /usr/local/bin/redirector

