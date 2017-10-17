# android-sign-utils
Forcefully make your data "compatible" with a different rom.

Originated from https://gist.github.com/ttimasdf/0cdd4b958dd00ff2bcdb125415aa1269

It reads your current system certificates(through connected adb devices) and replace them with ones specified from your OTA packages. Hopefully everything should have a backup.

# Usage

```
usage: certutils.py [-h] [-f ZIPFILE] [-t, --type cert_type] [-l] [-p] [-a]
                    [src]

Parse and manipulate Android certs

positional arguments:
  src                   device or packages.xml file

optional arguments:
  -h, --help            show this help message and exit
  -f ZIPFILE, --zipfile ZIPFILE
                        source ota zip to read new certs from
  -t, --type cert_type  certs to replace: testkey,platform,shared,media
  -l, --list            list certs in the device/file
  -p, --packages        print corresoponding packages when listing certs
  -a, --all             list all certs instead of 4 common certs
```

## Examples

Suppose you want to migrate to an community build, from official one(or whatever previously "incompatible"). **Reboot to recovery**, connect your phone to PC and invoke the following command.
```
./certutils.py -f ~/Downloads/lineage-14.1-20170930-UNOFFICIAL-Sultan-oneplus3.zip  # replace with your package
```
And flash the rom with TWRP normally. volia!


Suppose you want to inspect what your system is signed with. (have a look at releasekey) 
```
./certutils.py
```
Four key will be displayed by default: releasekey,platform,shared,media


If you want to enumerate all certs along with the packages they signed,
```
./certutils.py -l -a -p
```

You will get things like
```
==== Cert 0 ====

Issuer: C=86, ST=SZ, L=CN, O=tencent, OU=Android, CN=gz_tencent
Subject: C=86, ST=SZ, L=CN, O=tencent, OU=Android, CN=gz_tencent
SHA1 Fingerprint: 9A:DC:13:97:C5:0F:DC...
Cert: 30820237...
PubKey: MIGfMA0GCSqGSI...

Packages signed by cert:
- com.tencent.qqpimsecure.sc

==== Cert 1 ====

Issuer: C=cn...
```

Have a try guys! Issues and PR's are welcomed!

# Notes

ET snippets for use in this tool.
```py
# find index:
t.find('package[@name="{}"]//cert'.format(pkg)).attrib['index']
# get cert for specific index
t.find('package//cert[@key][@index={}]'.format(idx)).attrib['key']
```

# Packages used to gather certs
ContactsProvider com.android.providers.contacts : shared

CalendarProvider com.android.providers.calendar : testkey

DownloadProvider com.android.providers.downloads : media

TelephonyProvider com.android.providers.telephony : platform


read packages.xml and extract certs from it.
