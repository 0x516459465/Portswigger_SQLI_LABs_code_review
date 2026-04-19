"""
Django settings for the Oracle SQLi (query database version) lab.

Connects to the Oracle Database Free 23c service defined in
docker-compose. Credentials are read from env vars so the compose file
is the single source of truth.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = "lab-only-not-a-secret-do-not-reuse"

DEBUG = True

ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.staticfiles",
    "shop",
]

MIDDLEWARE = [
    "django.middleware.common.CommonMiddleware",
]

ROOT_URLCONF = "sqli_lab.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
            ],
        },
    },
]

WSGI_APPLICATION = "sqli_lab.wsgi.application"

ORACLE_HOST = os.environ.get("ORACLE_HOST", "db")
ORACLE_PORT = os.environ.get("ORACLE_PORT", "1521")
ORACLE_SERVICE = os.environ.get("ORACLE_SERVICE", "FREEPDB1")

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.oracle",
        "NAME": f"{ORACLE_HOST}:{ORACLE_PORT}/{ORACLE_SERVICE}",
        "USER": os.environ.get("ORACLE_USER", "system"),
        "PASSWORD": os.environ.get("ORACLE_PASSWORD", "labpassword"),
    }
}

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
