#!/bin/sh
set -e

retries=10
until python manage.py migrate --noinput; do
    retries=$((retries - 1))
    if [ "$retries" -le 0 ]; then
        echo "migrate failed after repeated retries; giving up." >&2
        exit 1
    fi
    echo "migrate failed; retrying in 3s ($retries retries left)..." >&2
    sleep 3
done

python manage.py seed

exec python manage.py runserver 0.0.0.0:8000
