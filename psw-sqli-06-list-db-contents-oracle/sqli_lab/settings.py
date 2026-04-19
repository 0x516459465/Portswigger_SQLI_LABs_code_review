"""
Django settings for the "list database contents (Oracle)" SQLi lab.

Connects to the Oracle Database Free 23c service defined in
docker-compose as a dedicated APP_USER so the enumeration surface
(USER_TABLES / USER_TAB_COLUMNS) contains only the lab schema.
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
    "django.contrib.sessions",
    "django.contrib.staticfiles",
    "shop",
]

MIDDLEWARE = [
    "django.middleware.common.CommonMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
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
        "USER": os.environ.get("ORACLE_USER", "labuser"),
        "PASSWORD": os.environ.get("ORACLE_PASSWORD", "labpassword"),
    }
}

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
