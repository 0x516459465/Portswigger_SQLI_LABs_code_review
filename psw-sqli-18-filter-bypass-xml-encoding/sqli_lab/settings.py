"""
Django settings for the "SQLi with filter bypass via XML encoding" lab.

SQLite is the backend. The vulnerable surface is a stock-check endpoint
that accepts an XML POST body of the form

    <stockCheck>
        <productId>1</productId>
        <storeId>1</storeId>
    </stockCheck>

A middleware-style WAF scans the raw request bytes for a blocklist of
SQL keywords (SELECT, UNION, FROM, WHERE) and rejects the request
with HTTP 403 if any appear. The XML parser then runs on whatever
got through and the extracted productId is concatenated into a raw
SQL query.

Because the parser decodes XML numeric character references
(`&#x55;NION` -> `UNION`) *after* the filter has inspected the raw
body, the keywords can be smuggled past the blocklist and reach the
SQL engine intact. The response of a stock-check is reflected
directly, so a UNION-based extraction of the administrator password
can be done in a single request.
"""

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
