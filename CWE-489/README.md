# Detect CWE-489 in Android Application

This scenario seeks to find **active debug code**.

## CWE-489: Active Debug Code

We analyze the definition of CWE-489 and identify its characteristics.

See [CWE-489](https://cwe.mitre.org/data/definitions/489.html) for more details.

![image](https://imgur.com/UuDNFXW.jpg)

## Code of CWE-489 in allsafe.apk

We use the [allsafe.apk](https://github.com/t0thkr1s/allsafe) sample to explain the vulnerability code of CWE-489.

![image](https://imgur.com/QSrATmt.jpg)

## CWE-489 Detection Process Using Quark Script API

![image](https://imgur.com/ydGfkV4.jpg)

First, we use Quark API ``getApplication(samplePath)`` to get the application element in the manifest file. Then we use ``applicationInstance.isDebuggable()`` to check if the application element sets the attribute ``android:debuggable`` to true. If **Yes**, that causes CWE-489 vulnerabilities.

## Quark Script CWE-489.py

![image](https://imgur.com/ToCAmD3.jpg)

```python
from quark.script import getApplication

SAMPLE_PATH = "allsafe.apk"

if getApplication(SAMPLE_PATH).isDebuggable():
    print(f"CWE-489 is detected in {SAMPLE_PATH}.")
```

## Quark Script Result

```TEXT
$ python3 CWE-489.py
CWE-489 is detected in allsafe.apk.
```
