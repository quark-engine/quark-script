# Detect CWE-297 in Android Application

This scenario seeks to find **Improper Validation of Certificate with Host Mismatch**.

## CWE-297: Improper Validation of Certificate with Host Mismatch

We analyze the definition of CWE-297 and identify its characteristics.

See [CWE-297](https://cwe.mitre.org/data/definitions/297.html) for more details.

![image](https://i.postimg.cc/PrpC3vgy/image.png)

## Code of CWE-297 in pivaa.apk

We use the [pivaa.apk](https://github.com/htbridge/pivaa) sample to explain the vulnerability code of CWE-297.

![image](https://i.postimg.cc/wT29kqv2/image.png)

## CWE-297 Detection Process Using Quark Script API

![image](https://i.postimg.cc/ryYJRWGN/image.png)

First, we use API ``findMethodImpls(samplePath, targetMethod)`` to locate the method that implements the hostname verification, which verifies the hostname of a certificate.

Next, we use API ``isMethodReturnAlwaysTrue(samplePath, targetMethod)`` to check if the method always returns true.

If the answer is **YES**, the method does not check the certificate of the host properly, which may cause CWE-297 vulnerability.

## Quark Script CWE-297.py

![image](https://i.postimg.cc/Dw311cSL/image.png)

```python
from quark.script import findMethodImpls, isMethodReturnAlwaysTrue

SAMPLE_PATH = "pivaa.apk"

ABSTRACT_METHOD = [
    "Ljavax/net/ssl/HostnameVerifier;",
    "verify",
    "(Ljava/lang/String; Ljavax/net/ssl/SSLSession;)Z"
]

for hostVerification in findMethodImpls(SAMPLE_PATH, ABSTRACT_METHOD):
    methodImpls = [
        hostVerification.className,
        hostVerification.methodName,
        hostVerification.descriptor
    ]
    if isMethodReturnAlwaysTrue(SAMPLE_PATH, methodImpls):
        print(f"CWE-297 is detected in method, {hostVerification.fullName}")
```

## Quark Script Result

```TEXT
$ python CWE-297.py
CWE-297 is detected in method, Lcom/htbridge/pivaa/handlers/API$1; verify (Ljava/lang/String; Ljavax/net/ssl/SSLSession;)Z
```
