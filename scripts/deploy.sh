#!/bin/bash

echo "Deploying AuthNexus..."
docker compose build
docker compose up -d --force-recreate
docker compose exec authnexus authnexus-cli migrate
