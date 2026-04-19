#!/bin/sh
set -e

# Oracle container signals healthy when listener accepts connections,
# but the PDB may still be opening. Retry migrate a few times so first
# boot does not race the database.
retries=10
until python manage.py migrate --noinput; do
    retries=$((retries - 1))
    if [ "$retries" -le 0 ]; then
        echo "migrate failed after repeated retries; giving up." >&2
        exit 1
    fi
    echo "migrate failed; retrying in 5s ($retries retries left)..." >&2
    sleep 5
done

python manage.py seed

exec python manage.py runserver 0.0.0.0:8000
