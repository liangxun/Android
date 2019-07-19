"""
https://github.com/MLDroid/drebin
"""
from PSCout import PSCOUT_SET


def GetBasicBlockDalvikCode(BasicBlock):
    '''
    Get the list of dalvik code of the instrcutions contained in the BasicBlock
    
    :param DVMBasicBlock BasicBlock
    :return DalvikCodeList
    :rtype List<String>
    '''

    DalvikCodeList = []
    for Instruction in BasicBlock.get_instructions():
        CodeLine = str(Instruction.get_name() + " " + Instruction.get_output())
        DalvikCodeList.append(CodeLine)
    return DalvikCodeList


def GetInvokedPscoutApis(DalvikCodeList):  
    DalvikCodeList = set(DalvikCodeList)
    ApiList = set()
    
    for DalvikCode in DalvikCodeList:
        if "invoke-" in DalvikCode:
            Parts = DalvikCode.split(",")
            for Part in Parts:
                if ";->" in Part:
                    Part = Part.strip()
                    FullApi = Part.split('(')[0].strip()
                    if FullApi in PSCOUT_SET:
                        print(FullApi)
                        ApiList.add(FullApi)
    return ApiList
