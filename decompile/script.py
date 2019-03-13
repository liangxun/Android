import os
import sys
import zipfile
from lxml import etree
import subprocess
from androguard.core.bytecodes.axml import AXMLPrinter
from androguard.util import read

from settings import *


def unzip(apk_path):
    if not os.path.isfile(apk_path):
        logger.error("{} is not a valid file.".format(apk_path.split('/')[-1]))
        raise AssertionError
    if len(apk_path) <=4 or apk_path[-4:] != ".apk":
        logger.error("{} is not a apk file.".format(apk_path))
        raise AssertionError
    zf = zipfile.ZipFile(apk_path, mode='r')
    dex = zf.extract("classes.dex", SCRIPT_PATH+'/data/{}'.format(apk_path.split('/')[-1]))
    xml = zf.extract("AndroidManifest.xml", SCRIPT_PATH+'/data/{}'.format(apk_path.split('/')[-1]))
    return dex, xml

def dex2smali(dex_path, out_path):
    smali_path = out_path+'/{}/smali'.format(dex_path.split('/')[-2])
    jar_path = SCRIPT_PATH + '/baksmali-2.2.6.jar'
    command = ['java', '-jar', jar_path, 'disassemble', dex_path, '-o', smali_path]
    retcode = subprocess.run(command)

def decode_manifest(xml_path, out_path):
    manifest = AXMLPrinter(read(xml_path)).get_xml_obj()
    buff = etree.tounicode(manifest, pretty_print=True)
    with open(out_path+'/{}/manifest.xml'.format(xml_path.split('/')[-2]), 'w') as f:
        f.write(buff)

def run(apks_path, out_path):
    cnt = 1
    for apk in os.listdir(apks_path):
        if os.path.exists(os.path.join(out_path, apk)):
            logger.info("{}, {} already exists".format(cnt, apk))
        else:
            logger.info("{}, {}".format(cnt, apk))
            iron_apk_path = os.path.join(apks_path, apk)
            try:
                os.mkdir(os.path.join(out_path, apk))
                dex, xml = unzip(iron_apk_path)
                decode_manifest(xml, out_path)
                dex2smali(dex, out_path)
                if CLEAN is True:
                    os.remove(dex)
                    os.remove(xml)
                    os.rmdir(SCRIPT_PATH+'/data/{}'.format(apk))
            except Exception as e:
                print(e)
                logger.error("{}, error".format(apk))
                pass
        cnt += 1
    

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("takes 1 argument.")
        print("Usage:")
        print("    $ python apks_path out_path")
    apks_path = sys.argv[1]
    out_path = sys.argv[2]
    '''
    apks_normal = apks_path+'/normal_apks'
    decompiled_normal = out_path+'/normal'
    run(apks_normal, decompiled_normal)
    '''
    apks_malware = apks_path+'/malware_apks'
    decompiled_malware = out_path+'/malware'
    run(apks_malware, decompiled_malware)
