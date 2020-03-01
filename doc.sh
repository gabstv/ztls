#!/bin/bash

PACKAGE=github.com/gabstv/ztls

mkdir -p /tmp/tmpgoroot/doc
rm -rf /tmp/tmpgopath/src/${PACKAGE}
mkdir -p /tmp/tmpgopath/src/${PACKAGE}
tar -c --exclude='.git' --exclude='tmp' --exclude='.env' . | tar -x -C /tmp/tmpgopath/src/${PACKAGE}
echo -e "go to: http://localhost:6070/pkg/${PACKAGE}\n"
open http://localhost:6070/pkg/${PACKAGE} &
GOROOT=/tmp/tmpgoroot/ GOPATH=/tmp/tmpgopath/ godoc -http=localhost:6070