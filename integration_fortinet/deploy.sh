#!/bin/bash

set -x

BASE_PATH="$(cd "$(dirname "$0")"; pwd -P)"

: "${MODE:=staging}"

if [ "$MODE" = "staging" ]; then
    docker-compose build --force-rm --parallel integration_fortinet_staging
    docker-compose up -d integration_fortinet_staging

elif [ "$MODE" = "production" ]; then
    docker-compose -f docker-compose.prod.yml build --force-rm --parallel integration_fortinet
    docker-compose -f docker-compose.prod.yml up -d integration_fortinet
fi
