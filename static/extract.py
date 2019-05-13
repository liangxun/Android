import os
import sys
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
            value = item.get(NS_ANDROID + 'name')
            if value is None:
                value = item.get('name')
                if value:
                    logger.warning("Failed to get the attribute '{}' on tag '{}' with namespace. "
                            "But found the same attribute without namespace!".format('name', '<uses-permission>'))
            uses_permissions.append(value)
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
    assert len(sys.argv) == 2
    tag = sys.argv[1]

    api_dict = '/home/security/Android/static/mapping_5.1.1.csv'
    path_decompiled = '/home/security/data/decompiled/{}'.format(tag)
    path_tpl = '/home/security/data/TPL/{}-tpl'.format(tag)

    out_path = "/home/security/data/reports/{}".format(tag)

    E = Extractor(path_decompiled, path_tpl, api_dict)

    apks_path = "/home/security/data/{}_apks".format(tag) # 遍历时用到最原始的apk目录，没有实际作用。因为反编译和提取第三方库都存在解析失败的APK,所以只有原始apk文件中的是全集
    
    cnt = 1
    error_cnt = 0
    for apk in os.listdir(apks_path):
        if os.path.exists(os.path.join(out_path, apk)):
            logger.info("{}, {} already exists".format(cnt, apk))
        else:
            try:
                logger.info("{}, {}".format(cnt, apk))
                a, b, c = E.extract(apk)
                report = {"permission": a, "sensitive_api": b, "tpl": c}
                report_file = os.path.join(out_path, apk)
                with open(report_file, 'w') as f:
                    json.dump(report, f, indent=4, sort_keys=True)
            except Exception as e:
                logger.error("{}, error \n{}".format(apk,e))
                error_cnt += 1
                pass
        cnt += 1
