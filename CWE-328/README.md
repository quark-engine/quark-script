## Detect CWE-328 in Android Application (allsafe.apk)

This scenario seeks to find **the use of weak Hash**. See [CWE-328](https://cwe.mitre.org/data/definitions/328.html) for more details.

Let’s use [allsafe.apk](https://github.com/t0thkr1s/allsafe), [ovaa.apk](https://github.com/oversecured/ovaa), [AndroGoat.apk](https://github.com/satishpatnayak/AndroGoat), [MSTG-Android-Java.apk](https://github.com/OWASP/MASTG-Hacking-Playground), and the above APIs to show how the Quark script finds this vulnerability.

First, we use API `findMethodInAPK(samplePath, targetMethod)` to find the method `MessageDigest.getInstance()` or `SecretKeyFactory.getInstance()`. Next, we use API `methodInstance.getArguments()` with a list to check if the method uses [weak hashing algorithms](https://en.wikipedia.org/wiki/Hash_function_security_summary). If **YES**, that causes CWE-328 vulnerability.

### Quark Script CWE-328.py
```python
from quark.script import findMethodInAPK

SAMPLE_PATHS = [
        "./allsafe.apk",   "./ovaa.apk",
        "./AndroGoat.apk", "./MSTG-Android-Java.apk"
]

TARGET_METHODS = [
    [
        "Ljava/security/MessageDigest;", "getInstance",
        "(Ljava/lang/String;)Ljava/security/MessageDigest;"
    ],
    [
        "Ljavax/crypto/SecretKeyFactory;", "getInstance",
        "(Ljava/lang/String;)Ljavax/crypto/SecretKeyFactory;"
    ]
]

HASH_KEYWORDS = [
    "MD2",  "MD4",  "MD5",      "PANAMA",
    "SHA0", "SHA1", "HAVAL128", "RIPEMD128"
]

for samplePath in SAMPLE_PATHS:

    methodsFound = []
    for target in TARGET_METHODS:
        methodsFound += findMethodInAPK(samplePath, target)

    for setHashAlgo in methodsFound:
        algoName = setHashAlgo.getArguments()[0].replace("-", "")

        if any(keyword in algoName for keyword in HASH_KEYWORDS):
            print(f"CWE-328 is detected in {samplePath},\n\t"
                  f"and it occurs in method, {setHashAlgo.fullName}")
```

### Quark Script Result
```
$ python CWE-328.py
CWE-328 is detected in ./allsafe.apk,
        and it occurs in method, Linfosecadventures/allsafe/challenges/SQLInjection; md5 (Ljava/lang/String;)Ljava/lang/String;
CWE-328 is detected in ./allsafe.apk,
        and it occurs in method, Lcom/google/firebase/database/core/utilities/Utilities; sha1HexDigest (Ljava/lang/String;)Ljava/lang/String;
CWE-328 is detected in ./allsafe.apk,
        and it occurs in method, Linfosecadventures/allsafe/challenges/WeakCryptography; md5Hash (Ljava/lang/String;)Ljava/lang/String;
CWE-328 is detected in ./ovaa.apk,
        and it occurs in method, Lorg/apache/commons/io/input/MessageDigestCalculatingInputStream; <init> (Ljava/io/InputStream;)V
CWE-328 is detected in ./AndroGoat.apk,
        and it occurs in method, Lowasp/sat/agoat/AccessControlIssue1Activity; hashPIN (Ljava/lang/String;)Ljava/lang/String;
CWE-328 is detected in ./MSTG-Android-Java.apk,
    and it occurs in method, Lcom/tozny/crypto/android/AesCbcWithIntegrity; generateKeyFromPassword (Ljava/lang/String; [B)Lcom/tozny/crypto/android/AesCbcWithIntegrity$SecretKeys;
```
