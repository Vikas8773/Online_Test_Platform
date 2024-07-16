import os
from pathlib import Path
import configparser
from datetime import timedelta
import dj_database_url

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Path to the server.properties file
config_file_path = BASE_DIR / 'Database' / 'server.properties'

# Reading Properties
config = configparser.RawConfigParser()

if os.path.exists(config_file_path):
    config.read(config_file_path)
    print(f"Loaded configuration from {config_file_path}")
else:
    print(f"Configuration file {config_file_path} not found. Falling back to environment variables.")

def configure_website(request):
    config_website = configparser.RawConfigParser()
    config_website.read(config_file_path)

    if not config_website.has_section('Server'):
        raise Exception("No 'Server' section found in the configuration file.")
        
    return {
        'Server_Title': config_website.get('Server', 'server.title'),
        'Server_Description': config_website.get('Server', 'server.description'),
        'Version': config_website.get('Server', 'server.version'),
    }

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv("SECRET_KEY", config.get('SecretSection', 'secret_key', fallback='your-default-secret-key'))

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv("DEBUG", config.getboolean('SecretSection', 'secret_debug', fallback=False))

ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", config.get('SecretSection', 'secret_host', fallback='*')).split()

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'drf_yasg',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',

    'Exam',
    'website',
    'api',
    'rest_framework',
    'corsheaders',
    
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    
]

ROOT_URLCONF = 'Exam.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, "templates")],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'Exam.settings.configure_website',
            ],
        },
    },
]

WSGI_APPLICATION = 'Exam.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'Exam',
        'USER': 'root',
        'PASSWORD': 'root',
        'HOST': 'localhost',   # Or an IP Address that your DB is hosted on
        'PORT': '3306',
    }
}
database_url=os.environ.get("DATABASE_URL")
DATABASES['default'] = dj_database_url.parse(database_url)
#postgresql://vikas:Uz5Yn5GXUZTBQ9wG0hsnDYIEXY6nNjh5@dpg-cqatkguehbks73df2v3g-a.oregon-postgres.render.com/onlinetestplatform_django_render

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

LANGUAGE_CODE = os.getenv('LANGUAGE_CODE', config.get('Server', 'server_language_code', fallback='en-us'))
TIME_ZONE = os.getenv('TIME_ZONE', config.get('Server', 'server_time_zone', fallback='UTC'))

USE_I18N = True
USE_L10N = True
USE_TZ = False

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_DIRS = [os.path.join(BASE_DIR, "static")]
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

EMAIL_BACKEND = os.getenv('EMAIL_BACKEND', config.get('Email', 'email_backend', fallback='django.core.mail.backends.smtp.EmailBackend'))
EMAIL_HOST = os.getenv('EMAIL_HOST', config.get('Email', 'email_host', fallback='smtp.gmail.com'))
EMAIL_PORT = int(os.getenv('EMAIL_PORT', config.getint('Email', 'email_port', fallback=587)))
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER', config.get('Email', 'email_host_user', fallback='your-email@example.com'))
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD', config.get('Email', 'email_host_password', fallback='your-email-password'))
EMAIL_USE_TLS = os.getenv('EMAIL_USE_TLS', config.getboolean('Email', 'email_use_tls', fallback=True))

EMAIL_FROM = str(os.getenv('EMAIL_FROM', config.get('Email', 'email_from', fallback='Online Test Platform')))

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

DATA_UPLOAD_MAX_MEMORY_SIZE = 50242880

CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=5),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=90),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": False,

    "ALGORITHM": "HS256",
    "VERIFYING_KEY":None,
    "AUDIENCE": None,
    "ISSUER": None,
    "JSON_ENCODER": None,
    "JWK_URL": None,
    "LEEWAY": 0,

    "AUTH_HEADER_TYPES": ("Bearer",),
    "AUTH_HEADER_NAME": "HTTP_AUTHORIZATION",
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
    "USER_AUTHENTICATION_RULE": "rest_framework_simplejwt.authentication.default_user_authentication_rule",

    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",),
    "TOKEN_TYPE_CLAIM": "token_type",
    "TOKEN_USER_CLASS": "rest_framework_simplejwt.models.TokenUser",

    "JTI_CLAIM": "jti",

    "SLIDING_TOKEN_REFRESH_EXP_CLAIM": "refresh_exp",
    "SLIDING_TOKEN_LIFETIME": timedelta(minutes=5),
    "SLIDING_TOKEN_REFRESH_LIFETIME": timedelta(days=1),

    "TOKEN_OBTAIN_SERIALIZER": "rest_framework_simplejwt.serializers.TokenObtainPairSerializer",
    "TOKEN_REFRESH_SERIALIZER": "rest_framework_simplejwt.serializers.TokenRefreshSerializer",
    "TOKEN_VERIFY_SERIALIZER": "rest_framework.simplejwt.serializers.TokenVerifySerializer",
    "TOKEN_BLACKLIST_SERIALIZER": "rest_framework.simplejwt.serializers.TokenBlacklistSerializer",
    "SLIDING_TOKEN_OBTAIN_SERIALIZER": "rest_framework.simplejwt.serializers.TokenObtainSlidingSerializer",
    "SLIDING_TOKEN_REFRESH_SERIALIZER": "rest_framework.simplejwt.serializers.TokenRefreshSlidingSerializer",
}

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
}
