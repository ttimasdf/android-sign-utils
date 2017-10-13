#!/usr/bin/env python3

import argparse
import os.path
import xml.etree.ElementTree as ET
from pathlib import Path
from tempfile import NamedTemporaryFile
import subprocess
import re


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
    parser.add_argument("src", help="device or packages.xml file")

    args = parser.parse_args()

    isFile = os.path.exists(args.src)
    if isFile:
        dst = open(args.src[:-4]+".modified.xml", 'w')
        tree = ET.parse(args.src)
    else:
        dst = NamedTemporaryFile('w')

        devices = dict(s.split('\t') for s in subprocess.check_output(['adb', 'devices'], encoding='utf8').strip().split('\n')[1:])
        assert devices and devices.popitem()[0].startswith(args.src), "Device not found"
        assert len(devices) == 0, "multiple devices connected"

        proc = subprocess.run('adb shell su root cat /data/system/packages.xml'.split(), stdout=subprocess.PIPE, encoding='utf8')
        assert proc.returncode == 0, "packages.xml read error"

        tree = ET.fromstring(proc.stdout)

    if args.list:
        if args.packages:
            cert_package_map = generateCertPkgMap(tree)
        if args.all:
            for node in tree.findall('package//cert[@key]'):
                idx = node.attrib['index']
                printCert(node.attrib['key'], idx)
                if args.packages:
                    printPkgs(cert_package_map, idx)
        else:
            for t, pkg in target_packages.items():
                idx = tree.find('package[@name="{}"]//cert'.format(pkg)).attrib['index']
                key = tree.find('package//cert[@key][@index="{}"]'.format(idx)).attrib['key']
                printCert(key, t)
                if args.packages:
                    printPkgs(cert_package_map, idx)


def printCert(cert, index=None):
    openssl_out = subprocess.check_output(
        'openssl x509 -noout -text -inform DER -fingerprint'.split(),
        input=bytes.fromhex(cert)).decode()
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
          "PubKey: {}\n".format(subject, issuer, sig[:20]+'...', cert, getPubKey(cert)))
          


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
        idx = pkg.find('**/[@index]').attrib['index']
        if idx not in ret:
            ret[idx] = []
        ret[idx].append(pkg.attrib['name'])
    return ret


def getPubKey(cert):
    openssl_out = subprocess.check_output("openssl x509 -inform DER -pubkey -noout".split(), input=bytes.fromhex(cert)).decode()
    return openssl_out.replace('\n', '')[26:-24]


if __name__ == '__main__':
    main()
