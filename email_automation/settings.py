"""
Django settings for email_automation project.

Generated by 'django-admin startproject' using Django 4.2.4.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

from pathlib import Path
import os
from huey import RedisHuey

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-i=c#8lv+a%)su6^tl3xgdr0eh60qph58*0u@(08+=q!5@)sw)r'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

EXTERNAL_APPS = [
    'email_app',
    'django_rq',
    # 'huey.contrib.djhuey'
    'background_task'
]

INSTALLED_APPS += EXTERNAL_APPS

# HUEY = {
#     'huey_class': 'huey.RedisHuey',  # Required.
#     'name': 'email_automation',                # Required.
#     'results': True,                 # Store return values of tasks.
#     'store_none': False,             # If a task returns None, do not save to results.
#     'immediate': False,              # If DEBUG=True, run synchronously.
#     'utc': True,                     # Use UTC for all times internally.
#     'connection': {
#         'host': '127.0.0.1',
#         'port': 6379,
#         'db': 0,
#         'connection_pool': None,      # Definitely you should use pooling!
#         'read_timeout': 1,            # If a queue is empty, timeout in 1 second.
#         'max_connections': None,      # Max. connections to keep open.
#         'health_check_interval': None,  # How often to run health checks.
#     },
#     'consumer': {
#         'workers': 4,
#         'worker_type': 'thread',      # Options are "thread" or "greenlet".
#         'initial_delay': 0.1,         # Smallest polling interval, same as -d.
#         'backoff': 1.15,              # Exponential backoff using this rate.
#         'max_delay': 10.0,            # Max possible polling interval, same as -m.
#         'scheduler_interval': 1,      # Check schedule every second, same as -s.
#         'periodic': True,             # Enable crontab feature.
#         'check_worker_health': True,  # Enable worker health checks.
#         'health_check_interval': 1,   # Check worker health every second.
#     },
# }

# BULLMQ_CONNECTION = {
#     'host': 'localhost',
#     'port': 6379,
#     'db': 0,
# }


RQ_QUEUES = {
    'default': {
        'HOST': 'localhost',
        'PORT': 6379,
        'DB': 0,
        'DEFAULT_TIMEOUT': 360,
    }
}

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'email_automation.urls'

# BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'email_automation.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'