# Detect CWE-532 in Android Application (dvba.apk)

This scenario seeks to find **insertion of sensitive information into
Log file**. See
[CWE-532](https://cwe.mitre.org/data/definitions/532.html) for more
details.

Let's use this
[APK](https://github.com/rewanthtammana/Damn-Vulnerable-Bank) and the
above APIs to show how the Quark script finds this vulnerability.

First, we use API `findMethodInAPK(samplePath, targetMethod)` to locate
`log.d` method. Then we use API `methodInstance.getArguments()` to get
the argument that input to `log.d`. Finally, we use some keywords such
as \"token\", \"password\", and \"decrypt\" to check if arguments
include sensitive data. If the answer is YES, that may cause sensitive
data leakage into log file.

You can use your own keywords in the keywords list to detect sensitive
data.

## Quark Script CWE-532.py

``` python
from quark.script import findMethodInAPK

SAMPLE_PATH = "dvba.apk"
TARGET_METHOD = [
    "Landroid/util/Log;",                       # class name
    "d",                                        # method name
    "(Ljava/lang/String; Ljava/lang/String;)I"  # descriptor
]
CREDENTIAL_KEYWORDS = [
    "token",
    "decrypt",
    "password"
]

methodsFound = findMethodInAPK(SAMPLE_PATH, TARGET_METHOD)

for debugLogger in methodsFound:
    arguments = debugLogger.getArguments()

    for keyword in CREDENTIAL_KEYWORDS:
        if keyword in arguments[1]:
            print(f"CWE-532 is detected in method, {debugLogger.fullName}")
```

## Quark Script Result

``` TEXT
$ python CWE-532.py
CWE-532 is detected in method, Lcom/google/firebase/auth/FirebaseAuth; d (Lc/c/b/h/o;)V
```
