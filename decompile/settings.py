import logging.config

LOG_CONF = "./logging.conf"
logging.config.fileConfig(LOG_CONF)
logger = logging.getLogger('decompile')
