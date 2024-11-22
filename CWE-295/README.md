# Detect CWE-295 in Android Application

This scenario seeks to find **Improper Certificate Validation**.

## CWE-295: Improper Certificate Validation

We analyze the definition of CWE-295 and identify its characteristics.

See [CWE-295](https://cwe.mitre.org/data/definitions/295.html) for more details.

![image](https://imgur.com/cuZ5qPp.jpg)

## Code of CWE-295 in InsecureShop.apk

We use the [InsecureShop.apk](https://github.com/hax0rgb/InsecureShop) sample to explain the vulnerability code of CWE-295.

![image](https://imgur.com/t7Y5clb.jpg)

## Quark Script CWE-295.py

To begin with, we use the API ``findMethodInAPK(samplePath, targetMethod)`` to locate all callers of method ``SslErrorHandler.proceed``.

Next, we must verify whether the caller overrides the method ``WebViewClient.onReceivedSslErroris``.

Therefore, we check if the method name and descriptor of the caller match those of ``WebViewClient.onReceivedSslErroris``. After that, we use the API ``methodInstance.findSuperclassHierarchy()`` to check if the superclasses of the caller include ``Landroid/webkit/WebViewClient``.

If both are **YES**, the APK will call ``SslErrorHandler.procees`` without certificate validation when an SSL error occurs, which may cause CWE-295 vulnerability.

```python
from quark.script import findMethodInAPK

SAMPLE_PATH = "insecureShop.apk"
TARGET_METHOD = [
    "Landroid/webkit/SslErrorHandler;",  # class name
    "proceed",                           # method name
    "()V"                                # descriptor
]
OVERRIDDEN_METHOD = [
    "Landroid/webkit/WebViewClient;",    # class name
    "onReceivedSslError",                # method name
    "(Landroid/webkit/WebView;" + " Landroid/webkit/SslErrorHandler;" + \
    " Landroid/net/http/SslError;)V"     # descriptor
]

for sslProceedCaller in findMethodInAPK(SAMPLE_PATH, TARGET_METHOD):
    if (
        sslProceedCaller.name == OVERRIDDEN_METHOD[1]
        and sslProceedCaller.descriptor == OVERRIDDEN_METHOD[2]
        and OVERRIDDEN_METHOD[0] in sslProceedCaller.findSuperclassHierarchy()
    ):
        print(f"CWE-295 is detected in method, {sslProceedCaller.fullName}")
```

## Quark Script Result

```TEXT
$　python3 CWE-295.py
CWE-295 is detected in method, Lcom/insecureshop/util/CustomWebViewClient; onReceivedSslError (Landroid/webkit/WebView; Landroid/webkit/SslErrorHandler; Landroid/net/http/SslError;)V
```
