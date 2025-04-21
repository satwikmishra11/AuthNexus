#!/bin/sh
set -e

# Wait for dependencies
if [ "$WAIT_FOR_REDIS" = "true" ]; then
  until nc -z redis 6379; do
    echo "Waiting for Redis..."
    sleep 2
  done
fi

exec "$@"
