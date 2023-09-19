from . import config

# If you want custom worker name
# NAME = 'worker-1024'

# If you want to use a dictConfig
# <https://docs.python.org/3/library/logging.config.html#logging-config-dictschema>
# for more complex/consistent logging requirements.
DICT_CONFIG = config.get()["rq"]["logging"]["dict_config"]
