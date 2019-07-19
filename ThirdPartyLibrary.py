import subprocess
import redis
import json
import config


def getThirdPartyLibrary(apk_file, sha256):
    """
    caller to literadar
    """
    command = ['python2', config.LiteRadar_scipt, apk_file]  # literadar noly support python2.
    subprocess.run(command)
    r = redis.Redis(host='localhost', port=6379, db=1)
    tpl = json.loads(r.get(sha256))
    return tpl