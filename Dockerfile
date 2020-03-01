FROM golang:1.13-alpine as base
LABEL maintainer="Gabriel Ochsenhofer (https://github.com/gabstv)"
ARG VERSION
RUN apk add --no-cache make git ca-certificates linux-headers wget curl
COPY . /ztls
WORKDIR /ztls/cmd/ztls
ENV GO111MODULE=on
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -ldflags="-s -w -X github.com/gabstv/ztls/internal/metadata.version=${VERSION}" -o /ztls/ztls.bin

FROM alpine
LABEL maintainer="Gabriel Ochsenhofer (https://github.com/gabstv)"
RUN mkdir -p /svc
COPY --from=base /ztls/ztls.bin /svc/ztls
WORKDIR /svc
ENV LOGLEVEL=warn
ENV LISTEN=:8080
ENTRYPOINT [ "/svc/ztls" "serve" ]