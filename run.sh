#!/bin/bash

if [[ $1 == "gen" ]];then
    go run cmd/ztls/main.go gen --output-dir tmp
    KEY0=$(base64 -i tmp/ca-key.pem)
    CERT0=$(base64 -i tmp/ca-cert.pem)
    PASS0=$(uuidgen)
    echo "SVC_KEY=base64:${KEY0}" > .env
    echo "SVC_CERT=base64:${CERT0}" >> .env
    echo "APIKEY=${PASS0}" >> .env
    echo "X-API-KEY: ${PASS0}"
    exit 0
fi

docker run --name ztls -p 8080:8080 --env-file .env gabs2/ztls:latest