from androguard.misc import AnalyzeAPK
import BasicBlockAttrBuilder
from utils import get_sha256
from ThirdPartyLibrary import getThirdPartyLibrary
import json
import sys
import time


def analyseAPK(apk_file):

    sha256 = get_sha256(apk_file)
    a, d, dx = AnalyzeAPK(apk_file)

    # ============== extract permissions ===============
    permissions = a.get_permissions()

    # ============== extract sensitiveApis ===============
    sensitiveApis = set()
    for dd in d:
        for method in dd.get_methods():
            g = dx.get_method(method)
            for BasicBlock in g.get_basic_blocks().get():
                instructions = BasicBlockAttrBuilder.GetBasicBlockDalvikCode(BasicBlock)
                PscoutApis = BasicBlockAttrBuilder.GetInvokedPscoutApis(instructions)
                sensitiveApis = sensitiveApis.union(PscoutApis)

    # ============== extract third-party-libraries ===========
    tpls = getThirdPartyLibrary(apk_file, sha256)

    return sha256, permissions, list(sensitiveApis), tpls


if __name__ == '__main__':
    "usage: python3 analysis.py xxx.apk"
    assert len(sys.argv) == 2
    apk_file = sys.argv[1]
    # apk_file = "/home/security/apk_sample/ffe88f6f33811af1b0ea42d0806b14b9.apk"
    start_time = time.time()
    sha256, permissions, sensitiveApis, tpls = analyseAPK(apk_file)
    print("============ uses-permissions =============")
    print(permissions)
    print("============= sensitive apis ==============")
    print(sensitiveApis)
    print("========== third party libraries =========")
    print(json.dumps(tpls, indent=4, sort_keys=True))
    print("sha256:", sha256)
    print("used time: {:.4f}s".format(time.time() - start_time))