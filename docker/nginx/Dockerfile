FROM nginx:latest

RUN apk add --no-cache --virtual openssl \
    && mkdir -p /app/public

COPY docker/nginx/conf/app.conf /etc/nginx/conf.d/default.conf
COPY --from=track-redir /go/bin/redirector /usr/local/bin/redirector

