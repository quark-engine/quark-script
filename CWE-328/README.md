# Detect CWE-328 in Android Application

This scenario seeks to find the **Use of Weak Hash**.

## CWE-328 Use of Weak Hash

We analyze the definition of CWE-328 and identify its characteristics.

See [CWE-328](https://cwe.mitre.org/data/definitions/328.html) for more details.

![image](https://imgur.com/DUaOaKi.jpg)

## Code of CWE-328 in allsafe.apk

We use the [allsafe.apk](https://github.com/t0thkr1s/allsafe) sample to explain the vulnerability code of CWE-328.

![image](https://imgur.com/nyreKX2.jpg)

## CWE-328 Detection Process Using Quark Script API

![image](https://imgur.com/bM7WJKo.jpg)

Let's use the above APIs to show how the Quark script finds this vulnerability.

First, we use API `findMethodInAPK(samplePath, targetMethod)` to find the method `MessageDigest.getInstance()` or `SecretKeyFactory.getInstance()`. Next, we use API `methodInstance.getArguments()` with a list to check if the method uses weak hashing algorithms. If **YES**, that causes CWE-328 vulnerability.

## Quark Script: CWE-328.py

![image](https://imgur.com/wb9Baa3.jpg)

```python
from quark.script import findMethodInAPK

SAMPLE_PATH = "./allsafe.apk"

TARGET_METHODS = [
    [
        "Ljava/security/MessageDigest;",
        "getInstance",
        "(Ljava/lang/String;)Ljava/security/MessageDigest;",
    ],
    [
        "Ljavax/crypto/SecretKeyFactory;",
        "getInstance",
        "(Ljava/lang/String;)Ljavax/crypto/SecretKeyFactory;",
    ],
]

HASH_KEYWORDS = [
    "MD2",
    "MD4",
    "MD5",
    "PANAMA",
    "SHA0",
    "SHA1",
    "HAVAL128",
    "RIPEMD128",
]

methodsFound = []
for target in TARGET_METHODS:
    methodsFound += findMethodInAPK(SAMPLE_PATH, target)

for setHashAlgo in methodsFound:
    algoName = setHashAlgo.getArguments()[0].replace("-", "")

    if any(keyword in algoName for keyword in HASH_KEYWORDS):
        print(
            f"CWE-328 is detected in {SAMPLE_PATH},\n\t"
            f"and it occurs in method, {setHashAlgo.fullName}"
        )
```

## Quark Script Result

```TEXT
$ python3 CWE-328.py
CWE-328 is detected in ./allsafe.apk,
        and it occurs in method, Linfosecadventures/allsafe/challenges/SQLInjection; md5 (Ljava/lang/String;)Ljava/lang/String;
CWE-328 is detected in ./allsafe.apk,
        and it occurs in method, Linfosecadventures/allsafe/challenges/WeakCryptography; md5Hash (Ljava/lang/String;)Ljava/lang/String;
CWE-328 is detected in ./allsafe.apk,
        and it occurs in method, Lcom/google/firebase/database/core/utilities/Utilities; sha1HexDigest (Ljava/lang/String;)Ljava/lang/String;
```
