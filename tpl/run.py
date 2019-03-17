import sys
import os
import hashlib
import json
from literadar import LibRadarLite
from _settings import logger


def extrct(apk_path, result_path):
    count = 0
    for apk in os.listdir(apk_path):
        if os.path.exists(os.path.join(result_path, apk)):
            print(count, apk, "already exists")
        else:
            print(count, apk)
            iron_apk_path = os.path.join(apk_path, apk)
            try:
                lrd = LibRadarLite(iron_apk_path)
                res = lrd.compare()
            # print(json.dumps(res, indent=4, sort_keys=True))
                tpl_file = os.path.join(result_path, apk)
                with open(tpl_file, 'w') as f:
                    json.dump(res, f,  indent=4, sort_keys=True)
            except:
                logger.error(apk, "error.")
                pass
        count += 1


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("takes 2 argument.")
        print("Usage:")
        print("    $ python input_path output_path")
    apk_path = sys.argv[1]
    result_path = sys.argv[2]
    extrct(apk_path, result_path)
