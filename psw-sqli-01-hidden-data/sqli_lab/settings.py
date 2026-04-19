"""
Django settings for the SQL-injection-in-WHERE-clause lab.

Intentionally minimal: single app, SQLite, DEBUG on so the reviewer can
see request/response details while testing.
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Static key; lab-only, never reuse.
SECRET_KEY = "lab-only-not-a-secret-do-not-reuse"

DEBUG = True

# Accept requests from any host when running the container.
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

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "shop.db",
    }
}

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
