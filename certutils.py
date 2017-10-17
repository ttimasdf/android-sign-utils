#!/usr/bin/env python3

import argparse
import os.path
import xml.etree.ElementTree as ET
from tempfile import NamedTemporaryFile
from time import time
import subprocess
import re
import zipfile


target_packages = {
    "releasekey": "com.android.providers.calendar",
    "shared": "com.android.providers.contacts",
    "media": "com.android.providers.downloads",
    "platform": "com.android.providers.telephony",
}


def main():
    parser = argparse.ArgumentParser(description="Parse and manipulate Android certs")
    parser.add_argument("-f", "--file", help="source ota zip to read new certs from")
    parser.add_argument("-t, --type", metavar="cert_type", help="certs to replace: testkey,platform,shared,media")
    parser.add_argument("-l", "--list", action='store_true', help="list certs in the device/file")
    parser.add_argument("-p", "--packages", action='store_true', help="print packages when listing certs")    
    parser.add_argument("-a", "--all", action='store_true', help="list all certs instead of 4 common certs")
    parser.add_argument("src", nargs='?', default='', help="device or packages.xml file")

    args = parser.parse_args()

    isFile = os.path.exists(args.src)
    if isFile:                                  # src is a file
        dst = open(args.src[:-4]+".modified.xml", 'w+b')
        tree = ET.parse(args.src)
    else:                                       # src is an adb device
        dst = NamedTemporaryFile(suffix=".xml")
        devices = dict(s.split('\t') for s in subprocess.check_output(['adb', 'devices'], encoding='utf8').strip().split('\n')[1:])  # get a dict {'serial': 'name'}
        assert devices, "No device connected"

        device = None
        cmd = ['adb', 'shell', 'cat', '/data/system/packages.xml']
        if len(devices) > 1:                              # with -s "device"
            for d, n in devices.items():
                if d.startswith(args.src):
                    device = d
                    cmd[1:1] = ['-s', device]
                    break
            assert device, "Device not found"
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, encoding='utf8')

        assert proc.returncode == 0, "packages.xml read error"

        tree = ET.fromstring(proc.stdout)
        with open('packages.adb_{:.0f}.xml'.format(time()), 'w') as f:
            print(f.write(proc.stdout), "bytes backed up to", f.name)


    if not args.file or args.list:              # -l : list certs
        if args.packages:                       # -p : list packages in cert entries
            cert_package_map = generateCertPkgMap(tree)

        if args.all:
            for node in tree.findall('package//cert[@key]'):  # find all certs with "key" attributes (cert may only stored once)
                idx = node.get('index')
                printCert(bytes.fromhex(node.get('key')), idx)
                if args.packages:
                    printPkgs(cert_package_map, idx)
        else:
            for t, pkg in target_packages.items():
                idx = tree.find('package[@name="{}"]//cert'.format(pkg)).get('index')
                key = tree.find('package//cert[@key][@index="{}"]'.format(idx)).get('key')
                printCert(bytes.fromhex(key), t)
                if args.packages:
                    printPkgs(cert_package_map, idx)
    else:
        assert zipfile.is_zipfile(args.file), "Not a valid ZIP archive"
        file = zipfile.ZipFile(args.file)
        pkcs7cert = file.read("META-INF/CERT.RSA")
        pemcert = subprocess.check_output("openssl pkcs7 -inform DER -print_certs".split(), input=pkcs7cert)
        dercert = subprocess.check_output('openssl x509 -outform DER'.split(), input=pemcert)

        print("\nTarget sign to replace:")
        printCert(dercert, "TARGET_FILE")

        assert input("Proceed?") == 'y', "User cancelled"
        
        # Change cert
        idx = tree.find('package[@name="{}"]//cert'.format(target_packages['releasekey'])).get('index')
        node = tree.find('package//cert[@key][@index="{}"]'.format(idx))
        oldcert = node.get('key')
        node.set('key', dercert.hex())

        # Change key
        oldkey = getPubKey(bytes.fromhex(oldcert))
        node = tree.find('keyset-settings/keys/public-key[@value="{}"]'.format(oldkey))
        node.set("value", getPubKey(dercert))

        # Write file
        assert not dst.closed, "output file closed? Whyyy??"
        payload = ET.tostring(tree)
        dst.write(payload)

        print("Modified file saved at", dst.name)
        if not isFile and input("Push back through ADB? [DANGEROUS]") == 'y':
            cmd = 'adb shell twrp'.split()
            if device:
                cmd[1:1] = ['-s', device]
            proc = subprocess.run(cmd)
            assert proc.returncode == 0, "Not in recovery!"
            cmd = ['adb', 'push', dst.name, '/data/system/packages.xml']
            if device:
                cmd[1:1] = ['-s', device]

            proc = subprocess.run(cmd)
            assert proc.returncode == 0, "Not in recovery or no root permission!"
            print("Push complete! retcode:", proc.returncode)


def printCert(cert, index=None):
    openssl_out = subprocess.check_output(
        'openssl x509 -noout -text -inform DER -fingerprint'.split(),
        input=cert).decode()
    subject = re.search("Subject:\s+(.*)", openssl_out)[1]
    issuer = re.search("Issuer:\s+(.*)", openssl_out)[1]
    # serial = re.search("Serial Number:\s+(.*)", openssl_out)[1]
    sig = re.search("SHA1 Fingerprint.*((?:[0-9A-F]{2}:){18})", openssl_out)[1]
    if index is not None:
        print("\n==== Cert {} ====\n".format(index))
    else:
        print("\n==== Cert ====\n")
    print("Issuer: {}\n"
          "Subject: {}\n"
          "SHA1 Fingerprint: {}\n"
          "Cert: {}\n"
          "PubKey: {}\n".format(subject, issuer, sig[:20]+'...', cert.hex(), getPubKey(cert)))


def printPkgs(m, idx):
    print("Packages signed by cert:")
    if idx not in m:
        print("NONE")
        return
    for pkg in m[idx]:
        print('-', pkg)


def generateCertPkgMap(tree):
    ret = {}
    for pkg in tree.findall("package"):
        idx = pkg.find('**/[@index]').get('index')
        if idx not in ret:
            ret[idx] = []
        ret[idx].append(pkg.get('name'))
    return ret


def getPubKey(cert):
    openssl_out = subprocess.check_output("openssl x509 -inform DER -pubkey -noout".split(), input=cert).decode()
    return openssl_out.replace('\n', '')[26:-24]


if __name__ == '__main__':
    try:
        main()
    except AssertionError as e:
        print("Error:", str(e))
