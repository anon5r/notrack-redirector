FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY src ./src
RUN CGO_ENABLED=0 go build -o /go/bin/redirector ./src


FROM alpine:3
# 上流の HTTPS 取得に CA 証明書が必要。
RUN apk add --no-cache ca-certificates
COPY --from=build /go/bin/redirector /usr/local/bin/redirector
EXPOSE 9000

ENTRYPOINT ["/usr/local/bin/redirector"]
