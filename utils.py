import hashlib


def get_sha256(apk_file):
    with open(apk_file,'rb') as f:
        data = f.read()
    # md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return sha256