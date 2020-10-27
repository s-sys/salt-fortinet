#!/bin/bash

set -x

BASE_PATH="$(cd "$(dirname "$0")"; pwd -P)"

: "${MODE:=staging}"

if [ "$MODE" = "staging" ]; then
    docker-compose rm -sf integration_fortinet_staging

elif [ "$MODE" = "production" ]; then
    docker-compose -f docker-compose.prod.yml rm -sf integration_fortinet
fi
