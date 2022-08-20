FROM golang:alpine AS build
COPY src/main/main.go src/main.go
RUN go build -o /go/bin/redirector src/main.go


FROM golang:alpine

COPY --from=build /go/bin/redirector /go/bin/redirector
EXPOSE 9000

ENTRYPOINT ["/go/bin/redirector"]
