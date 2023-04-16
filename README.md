Anti-Tracking URL Redirector
====

Bypass URLs for affiliate advertising and tracking and redirect directly to the original destination URL in the parameters.

It can be used by DNS transitioning the hostname of the tracking service to the host where this service is running.

However, _services that use HTTPS will be detected as invalid URLs._

# What can I do

If a specific parameter is included, it is taken as the URL to redirect to and a Location header is returned



# How to Build

## Go

```shell
$ go build -o dist/track-redir src/main/main.go
```

## Docker

```shell
$ docker build -t track-redir:latest -f docker/golang/Dockerfile .
```

### Running on Docker container

```shell
$ docker run --rm --name redirgo -p 9090:9090 track-redir
```



# Debug

## Go

```shell
$ go run src/main/main.go
```

then you can go http://localhost:9090


# Supported track URL patterns

- https://px.a8.net/svt/ejp?a8mat=http...
- https://hb.afl.rakuten.co.jp/ichiba/123456abc....a6bc789d/...?pc=http...&m=http...
- https://hb.afl.rakuten.co.jp/hgc/123456abc.....a6bc789d/...?pc=http...
- https://ck.jp.ap.valuecommerce.com/servlet/referral?sid=...&pid=...&vc_url=http...
