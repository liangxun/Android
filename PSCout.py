import config

def getPscoutApis(pscout_file):
    APIs = set()
    with open(pscout_file, 'r') as f:
        for line in f.readlines():
            apiparts = line.split(',')
            CallerClass = apiparts[0].strip()
            CallerMehod = apiparts[1].strip()
            api = 'L' + CallerClass + ';->' + CallerMehod
            APIs.add(api)
    # print("build dict: contain {} sensitive APIs.".format(len(APIs)))
    return APIs

PSCOUT_SET = getPscoutApis(config.Pscout_file)