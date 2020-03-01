#!/bin/bash

go mod vendor

VERSION=$(cat .version)

echo $VERSION

docker build --build-arg VERSION=${VERSION} -t gabs2/ztls:latest \
  -t gabs2/ztls:v${VERSION} .
