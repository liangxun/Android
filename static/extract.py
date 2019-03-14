import os
from lxml import etree
import json
import logging.config

log_conf = "./logging.conf"
logging.config.fileConfig(log_conf)
logger = logging.getLogger('report')

NS_ANDROID_URI = 'http://schemas.android.com/apk/res/android' 
NS_ANDROID = '{{{}}}'.format(NS_ANDROID_URI)


class Extractor:
    def __init__(self, path_decompiled, path_tpl, api_dict):
        self.path_decompiled = path_decompiled
        self.path_tpl = path_tpl
        self.sensitive_apis = self.getSensitiveAPIs(api_dict)
    
    def getSensitiveAPIs(self, api_dict):
        """建立敏感API字典"""
        APIs = set()
        with open(api_dict, 'r') as f:
            for line in f.readlines():
                CallerClass, CallerMehod = line.split(',')[:2]
                api = 'L' + CallerClass + ';->' + CallerMehod
                api = api.strip()
                # if api in APIs:
                    # print("Redundant api: {}".format(api))
                APIs.add(api)
        print("build dict: contain {} sensitive APIs.".format(len(APIs)))
        return APIs

    def parse_manifest(self, xml_path):
        xml = etree.parse(xml_path)
        uses_permissions = []
        for item in xml.findall("uses-permission"):
            uses_permissions.append(item.get(NS_ANDROID + 'name'))
        return uses_permissions

    def get_tpl(self, tpl_path):
        with open(tpl_path, 'r') as f:
            record = json.load(f)
        tpls = []
        for item in record:
            tpls.append((item['Library'], item['Package'], item['Standard Package']))
        return tpls

    def analysis_smali(self, smali_path, tpls):
        tpl_codes = set()
        for _, tpl, _ in tpls:
            tpl = tpl[1:]    # Literadar提取的Package默认第一个字母为L，去掉
            root_tpl = os.path.join(smali_path, tpl)
            for a, _, _ in os.walk(root_tpl):
                tpl_codes.add(a)
        all_apis = set()
        for a, _, c in os.walk(smali_path):
            if a not in tpl_codes:    # 不统计第三方库中的api调用情况
                for file in c:
                    single_smali_file = os.path.join(a,file)
                    # print(single_smali_file)
                    apis = self.extract_api(single_smali_file)
                    all_apis = all_apis | apis
        return all_apis

    def extract_api(self, smali_file):
        apis = set()
        with open(smali_file, 'r') as f:
            for line in f.readlines():
                line = line.strip()
                if line.startswith('invoke'):
                    func = line.split(' ')[-1]
                    func = func[:func.index('(')]
                    if func in self.sensitive_apis:
                        # print(func)
                        apis.add(func)
        return apis

    def extract(self, apk):
        smali_path = os.path.join(self.path_decompiled, apk, 'smali')
        manifest_path = os.path.join(self.path_decompiled, apk, 'manifest.xml')
        tpl_path = os.path.join(self.path_tpl, apk)
        uses_permissions = self.parse_manifest(manifest_path)
        tpls = self.get_tpl(tpl_path)
        apis = self.analysis_smali(smali_path, tpls)
        return uses_permissions, list(apis), tpls


if __name__ == '__main__':
    api_dict = '/home/thinker/Projects/Android/data/mapping_5.1.1.csv'

    path_decompiled = '/media/thinker/DATA/BUPT/Codes/Data/SoftwareSecurity/decompiled/malware'
    path_tpl = '/media/thinker/DATA/BUPT/Codes/Data/SoftwareSecurity/TPL/malware-tpl'
    out_path = "/home/thinker/Projects/Android/data/malware_report"
    E = Extractor(path_decompiled, path_tpl, api_dict)
    # apk = '44cf724e3c80c2eea38ba1020bc67f52.apk'
    apks_path = "/media/thinker/DATA/BUPT/Codes/Data/SoftwareSecurity/malware_apks"
    cnt = 1
    for apk in os.listdir(apks_path):
        if os.path.exists(os.path.join(out_path, apk)):
            logger.info("{}, {} already exists".format(cnt, apk))
        else:
            try:
                logger.info("{}, {}".format(cnt, apk))
                a, b, c = E.extract(apk)
                report = {"permission": a, "sensitive_api": b, "tpl": c}
                # print(json.dumps(report, indent=4, sort_keys=True))
                report_file = os.path.join(out_path, apk)
                with open(report_file, 'w') as f:
                    json.dump(report, f, indent=4, sort_keys=True)
            except Exception as e:
                logger.error("{}, error \n{}".format(apk,e))
                pass
        cnt += 1
