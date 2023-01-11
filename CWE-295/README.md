# Detect CWE-295 in Android Application (InsecureShop.apk)

This scenario seeks to find **Improper Certificate Validation**. See [CWE-295](https://cwe.mitre.org/data/definitions/295.html) for more details.

Let’s use this [APK](https://github.com/hax0rgb/InsecureShop) and the above APIs to show how the Quark script finds this vulnerability.

We use the API `findMethodInAPK` to locate all `SslErrorHandler.proceed` methods. Then we need to identify whether the method `WebViewClient.onReceivedSslError` is overridden by its subclass. 

First, we check and make sure that the `MethodInstance.name` is `onReceivedSslError`, and the `MethodInstance.descriptor` is `(Landroid/webkit/WebView; Landroid/webkit/SslErrorHandler; Landroid/net/http/SslError;)V`.

Then we use the API `MethodInstance.findSuperclassHierarchy` to get the superclass list of the method's caller class.

Finally, we check the `Landroid/webkit/WebViewClient;` is on the superclass list. If **YES**, that may cause CWE-295 vulnerability.

## API Spec
**MethodInstance.findSuperclassHierarchy()**
* **Description:** Find all superclasses of this method object.
* **params:** None
* **Return:** Python list contains all superclass names of this method.


## Quark Script CWE-295.py
```python
from quark.script import findMethodInAPK

SAMPLE_PATH = "insecureShop.apk"
TARGET_METHOD = [
    "Landroid/webkit/SslErrorHandler;",  # class name
    "proceed",                           # method name
    "()V"                                # descriptor
]
OVERRIDE_METHOD = [
    "Landroid/webkit/WebViewClient;",    # class name
    "onReceivedSslError",                # method name
    "(Landroid/webkit/WebView;"+" Landroid/webkit/SslErrorHandler;" + \
    " Landroid/net/http/SslError;)V"     # descriptor
]

for sslProceedCaller in findMethodInAPK(SAMPLE_PATH, TARGET_METHOD):
    if (sslProceedCaller.name == OVERRIDE_METHOD[1] and
       sslProceedCaller.descriptor == OVERRIDE_METHOD[2] and
       OVERRIDE_METHOD[0] in sslProceedCaller.findSuperclassHierarchy()):
        print(f"CWE-295 is detected in method, {sslProceedCaller.fullName}")

```
## Quark Script Result
```
$ python3 CWE-295.py
Requested API level 29 is larger than maximum we have, returning API level 28 instead.
CWE-295 is detected in method, Lcom/insecureshop/util/CustomWebViewClient; onReceivedSslError (Landroid/webkit/WebView; Landroid/webkit/SslErrorHandler; Landroid/net/http/SslError;)V
```
