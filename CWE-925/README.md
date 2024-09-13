# Detect CWE-925 in Android Application


This scenario seeks to find **Improper Verification of Intent by
Broadcast Receiver** in the APK file.

## CWE-925 Improper Verification of Intent by Broadcast Receiver

We analyze the definition of CWE-925 and identify its characteristics.

See [CWE-925](https://cwe.mitre.org/data/definitions/925.html) for more
details.

![image](https://imgur.com/fMZ2bMN.jpg)

## Code of CWE-925 in InsecureBankv2.apk

We use the
[InsecureBankv2.apk](https://github.com/dineshshetty/Android-InsecureBankv2)
sample to explain the vulnerability code of CWE-925.

![image](https://imgur.com/V7VtL3x.jpg)

## Quark Script CWE-925.py

First, we use API `getReceivers(samplePath)` and
`receiverInstance.isExported()` to find all the exported receivers
defined in the APK.

Second, we use API
`checkMethodCalls(samplePath, targetMethod, checkMethods)` to check if
the `onReceive` method of every exported receiver obtains intent action.

If **No**, it could imply that the APK does not verify intent properly,
potentially leading to a CWE-925 vulnerability.

``` python
from quark.script import checkMethodCalls, getReceivers

sample_path = "InsecureBankv2.apk"

TARGET_METHOD = [
    '',
    'onReceive',
    '(Landroid/content/Context; Landroid/content/Intent;)V'
]

CHECK_METHODS = [
    ['Landroid/content/Intent;', 'getAction', '()Ljava/lang/String;']
]

receivers = getReceivers(sample_path)
for receiver in receivers:
    if receiver.isExported():
        className = "L"+str(receiver).replace('.', '/')+';'
        TARGET_METHOD[0] = className
        if not checkMethodCalls(sample_path, TARGET_METHOD, CHECK_METHODS):
            print(f"CWE-925 is detected in method, {className}")
```

## Quark Script Result

``` TEXT
$ python CWE-925.py
CWE-925 is detected in method, Lcom/android/insecurebankv2/MyBroadCastReceiver;
```
