# Detect CWE-925 in Android Application (InsecureBankv2, AndroGoat)

This scenario seeks to find **Improper Verification of Intent by Broadcast Receiver**. See [CWE-925](https://cwe.mitre.org/data/definitions/925.html) for more details.

Let’s use both two of apks ([InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2) and [AndroGoat](https://github.com/satishpatnayak/AndroGoat)) to show how the Quark script finds this vulnerability.

In the first step, we use the `getReceivers` API to find all `Receiver` components defined in the Android application. Then, we exclude any receivers that are not exported.

In the second step, our goal is to verify the **intentAction** is properly validated in each receiver which is identified in the previous step. To do this, we use the `checkMethodCalls` function.

Finally, if any receiver's **onReceive** method exhibits improper verification on **intentAction**, it could indicate a potential CWE-925 vulnerability.

## API Spec
**receiverInstance.hasIntentFilter()**
* **Description:** Check if the receiver has an intent-filter.
* **params:** None
* **Return:** True/False

**receiverInstance.isExported()**
* **Description:** Check if the receiver is exported.
* **params:** None
* **Return:** True/False

**getReceivers(samplePath)**
* **Description:** Get receivers from a target sample.
* **params:**
    * samplePath:  target file
* **Return:** python list containing receivers

**checkMethodCalls(samplePath, targetMethod, checkMethods)**
* **Description:**  Check if any of the specific methods shown in the `targetMethod`
* **params:**
    * samplePath: target file
    * targetMethod:  python list contains the class name,method name, and descriptor of the target method or a Method Object.
    * checkMethods: python list contains the class name, method name, and descriptor of the target method.
* **Return:** bool that indicate specific methods can be called or defined within a `target method` or not.


## Quark Script CWE-925.py
```python
from quark.script import checkMethodCalls, getReceivers

SAMPLE_PATHS = ["AndroGoat.apk", "InsecureBankv2.apk"]

TARGET_METHOD = [
    '',
    'onReceive',
    '(Landroid/content/Context; Landroid/content/Intent;)V'
]

CHECK_METHODS = [
    ['Landroid/content/Intent;', 'getAction', '()Ljava/lang/String;']
]

for filepath in SAMPLE_PATHS:
    receivers = getReceivers(filepath)
    for receiver in receivers:
        if receiver.isExported():
            className = "L"+str(receiver).replace('.', '/')+';'
            TARGET_METHOD[0] = className
            if not checkMethodCalls(filepath, TARGET_METHOD, CHECK_METHODS):
                print(f"CWE-925 is detected in method, {className}")

```
## Quark Script Result
```
$ python CWE-925.py
CWE-925 is detected in method, Lowasp/sat/agoat/ShowDataReceiver;
CWE-925 is detected in method, Lcom/android/insecurebankv2/MyBroadCastReceiver;
```
