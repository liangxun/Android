from androguard.misc import AnalyzeAPK
import BasicBlockAttrBuilder
from utils import get_sha256

def analyseAPK(apk_file):

    sha256 = get_sha256(apk_file)
    
    a, d, dx = AnalyzeAPK(apk_file)
    # ============== extract permissions ===============
    permissions = a.get_permissions()

    # ============== extract sensitiveApis ===============
    SensitiveApis = set()
    for dd in d:
        for method in dd.get_methods():
            g = dx.get_method(method)
            for BasicBlock in g.get_basic_blocks().get():
                instructions = BasicBlockAttrBuilder.GetBasicBlockDalvikCode(BasicBlock)
                PscoutApis = BasicBlockAttrBuilder.GetInvokedPscoutApis(instructions)
                SensitiveApis.union(PscoutApis)

    # ============== extract third-party-libraries ===========


if __name__ == '__main__':
    analyseAPK('/home/security/apk_sample/ffe88f6f33811af1b0ea42d0806b14b9.apk')