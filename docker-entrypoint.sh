#!/bin/bash
set -e

# Run Alembic migrations only if starting uvicorn (not for workers or other commands)
if echo "$@" | grep -q "uvicorn"; then
    echo "Running database migrations..."
    alembic upgrade head
fi

echo "Starting: $@"
exec "$@"
