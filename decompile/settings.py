import os
import logging.config


SCRIPT_PATH = os.path.split(os.path.realpath(__file__))[0]

LOG_CONF = "./logging.conf"
logging.config.fileConfig(LOG_CONF)
logger = logging.getLogger('decompile')

CLEAN = True #remove dex and androidmanifest.xml(binary)