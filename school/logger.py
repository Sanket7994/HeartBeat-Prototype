import os
import logging

from .settings import BASE_DIR
from .settings import DEBUG

# Usage in other modules:
#
#     from djangoproject.logger import log
#     log.info('some output')
#
# Note, doing this manually in other modules results in nicer output:
#
#     import logging
#     log = logging.getLogger(__name__)
#     log.info('some output')

# the basic logger other apps can import
log = logging.getLogger(__name__)

# the minimum reported level
if DEBUG:
    min_level = 'DEBUG'
else:
    min_level = 'INFO'

# the minimum reported level for Django's modules
# optionally set to DEBUG to see database queries etc.
# or set to min_level to control it using the DEBUG flag
min_django_level = 'INFO'

# logging dictConfig configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,  # keep Django's default loggers
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(asctime)s %(module)s %(process)d %(thread)d %(message)s',
        },
        'simple': {
            'format': '%(levelname)s %(message)s',
        },
        'timestampthread': {
            'format': "%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s] [%(name)-20.20s]  %(message)s",
        },
    },
    'filters': {
        'exclude_reload': {
            'base_app': 'base_app.logging_filters.ExcludeReloadFilter',
        },
    },
    'handlers': {
        'null': {
            'level': 'DEBUG',
            'class': 'logging.NullHandler',
        },
        'logfile': {
            'level': min_level,  # this level or higher goes to the log file
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(BASE_DIR, 'djangoproject.log'),  # replace with your desired logfile name
            'maxBytes': 1024 * 1024 * 5,  # 5 MB
            'backupCount': 3,
            'formatter': 'timestampthread',
            'filters': ['exclude_reload'],  # apply the exclude_reload filter
        },
        'console': {
            'level': min_level,  # this level or higher goes to the console
            'class': 'logging.StreamHandler',
            'filters': ['exclude_reload'],  # apply the exclude_reload filter
        },
    },
    'loggers': {
        'django': {
            'handlers': ['logfile', 'console'],
            'level': min_django_level,  # this level or higher goes to the console
            'propagate': False,
        },
        'base_app': {
            'handlers': ['logfile', 'console'],
            'level': min_level,  # this level or higher goes to the console
        },
    },
}
