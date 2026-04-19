"""
Django settings for the "Blind SQLi with out-of-band data exfiltration" lab.

PostgreSQL is the backend. The lab stands up three containers on a
private Docker network: db (Postgres + dblink), oob (a stand-in for
Burp Collaborator that also parses the libpq startup message so
exfiltrated parameters are readable), and web (this Django app).

An injected `dblink_connect()` that embeds the administrator password
into a libpq connection-string parameter will make Postgres open a
TCP connection to the oob recorder and send the password inside the
Postgres wire-protocol startup message. The web view polls the
recorder's HTTP log, which surfaces those parsed parameters so the
learner can read the exfiltrated value directly.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = "lab-only-not-a-secret-do-not-reuse"

DEBUG = False

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

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("POSTGRES_DB", "labdb"),
        "USER": os.environ.get("POSTGRES_USER", "labuser"),
        "PASSWORD": os.environ.get("POSTGRES_PASSWORD", "labpass"),
        "HOST": os.environ.get("POSTGRES_HOST", "db"),
        "PORT": os.environ.get("POSTGRES_PORT", "5432"),
    }
}

OOB_LOG_URL = os.environ.get("OOB_LOG_URL", "http://oob:8080/log")
OOB_HOSTNAME = os.environ.get("OOB_HOSTNAME", "oob")

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
