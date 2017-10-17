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
