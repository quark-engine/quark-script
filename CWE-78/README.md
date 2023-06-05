Detect CWE-78 in Android Application (Vuldroid.apk )
-----------------------------------------------------------------------
This scenario seeks to find **Improper Neutralization of Special Elements used in an OS Command**. See [CWE-78](https://cwe.mitre.org/data/definitions/78.html) for more details.

Let’s use this [APK](https://github.com/jaiswalakshansh/Vuldroid) and the above APIs to show how the Quark script finds this vulnerability.

First, we design a detection rule ``ExternalStringsCommands.json`` to spot on behavior using external strings as commands.

Next, we use Quark API ``behaviorInstance.getMethodsInArgs()`` to check if any APIs in the caller method for string matching. 

If NO, the APK does not neutralize special elements within the argument, which may cause CWE-78 vulnerability. 

If YES, check if there are any special elements used in string matching for a filter. If NO, the APK does not neutralize special elements within the argument, which may cause CWE-78 vulnerability. 


Quark Script CWE-78.py
=======================

The Quark Script below uses Vuldroid.apk to demonstrate.

``` python
from quark.script import runQuarkAnalysis, Rule, findMethodInAPK

SAMPLE_PATH = "Vuldroid.apk"
RULE_PATH = "ExternalStringCommand.json"


STRING_MATCHING_API = set([
    ("Ljava/lang/String;", "contains", "(Ljava/lang/CharSequence)Z"),
    ("Ljava/lang/String;", "indexOf", "(I)I"),
    ("Ljava/lang/String;", "indexOf", "(Ljava/lang/String;)I"),
    ("Ljava/lang/String;", "matches", "(Ljava/lang/String;)Z"),
    ("Ljava/lang/String;", "replaceAll", "(Ljava/lang/String; Ljava/lang/String;)Ljava/lang/String;")
])

specialElementsPattern = r"[ ;|,>`]+"

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for ExternalStringCommand in quarkResult.behaviorOccurList:

    methodCalled = set()
    caller = ExternalStringCommand.methodCaller

    for method in ExternalStringCommand.getMethodsInArgs():
        methodCalled.add(method.fullName)

    if methodCalled.intersection(STRING_MATCHING_API):
        if not ExternalStringCommand.hasString(specialElementsPattern):
            print(f"CWE-78 is detected in method, {caller.fullName}")
    else:
        print(f"CWE-78 is detected in method, {caller.fullName}")

```
                
Quark Rule: ExternalStringCommand.json
=========================================

```json
{
    "crime": "Using external strings as commands",
    "permission": [],
    "api": [
        {
            "class": "Landroid/content/Intent;",
            "method": "getStringExtra",
            "descriptor": "(Ljava/lang/String;)Ljava/lang/String"
        },
        {
            "class": "Ljava/lang/Runtime;",
            "method": "exec",
            "descriptor": "(Ljava/lang/String;)Ljava/lang/Process"
        }
    ],
    "score": 1,
    "label": []
}
```

Quark Script Result
======================
- **Vuldroid.apk**

```
$ python3 CWE-78.py
CWE-78 is detected in method, Lcom/vuldroid/application/RootDetection; onCreate (Landroid/os/Bundle;)V
```
