# If you want custom worker name
# NAME = 'worker-1024'

# If you want to use a dictConfig
# <https://docs.python.org/3/library/logging.config.html#logging-config-dictschema>
# for more complex/consistent logging requirements.
DICT_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {"format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"},
    },
    "handlers": {
        "default": {
            # 'level': 'INFO',
            "formatter": "standard",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stderr",  # Default is stderr
        },
    },
    "loggers": {
        "root": {  # root logger
            "handlers": ["default"],
            "level": "INFO",
            "propagate": False,
        },
        "zeek_benchmarker.tasks": {  # Use debug level for tasks logger.
            "level": "DEBUG",
            "propagate": True,
        },
    },
}
