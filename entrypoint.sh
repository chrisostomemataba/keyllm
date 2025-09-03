#!/bin/sh
set -e

# Run migrations
echo "Running database migrations..."
/app/keyllm -migrate

# Execute the main container command (which is to start the server)
exec "$@"