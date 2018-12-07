#!/usr/bin/env bash

set -e

CGO_ENABLED=0 GOOS=linux go build -a -tags netgo -ldflags '-w' .
docker build -t zm/o_cap .
docker run -it zm/o_cap:latest bash
