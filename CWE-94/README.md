# Detect CWE-94 in Android Application

This scenario seeks to find **code injection** in the APK file. 

## CWE-94: Improper Control of Generation of Code

We analyze the definition of CWE-94 and identify its characteristics.

See [CWE-94](https://cwe.mitre.org/data/definitions/94.html) for more details.

![image](https://imgur.com/M9Jlgrn.png)

## Code of CWE-94 in ovaa.apk

We use the [ovaa.apk](https://github.com/oversecured/ovaa) sample to explain the vulnerability code of CWE-94.

![image](https://imgur.com/MdlAnvu.png)

## CWE-94 Detection Process Using Quark Script API

Let's use the above APIs to show how the Quark script finds this vulnerability.

First, we design a detection rule ``loadExternalCode.json`` to spot on behavior using the method ``createPackageContext``. Then, we find the caller method that calls the ``createPackageContext``. Finally, we check if the method ``checkSignatures`` is called in the caller method for verification.

![image](https://imgur.com/6cPBMWP.jpg)

## Quark Script: CWE-94.py

![image](https://imgur.com/Aw26Lv2.jpg)

```python
from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "ovaa.apk"
RULE_PATH = "loadExternalCode.json"

targetMethod = [
        "Landroid/content/pm/PackageManager;",
        "checkSignatures",
        "(Ljava/lang/String;Ljava/lang/String;)I"
        ]

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for ldExternalCode in quarkResult.behaviorOccurList:

    callerMethod = [
            ldExternalCode.methodCaller.className,
            ldExternalCode.methodCaller.methodName,
            ldExternalCode.methodCaller.descriptor
            ]

    if not quarkResult.findMethodInCaller(callerMethod, targetMethod):
        print(f"Method: {targetMethod[1]} not found!")
        print(f"CWE-94 is detected in {SAMPLE_PATH}")
```

## Quark Rule: loadExternalCode.json

![image](https://imgur.com/IHENeJx.jpg)

```json
{
    "crime": "Load external code from other APK.",
    "permission": [],
    "api": [
        {
            "descriptor": "(Ljava/lang/String;I)Landroid/content/Context;",
            "class": "",
            "method": "createPackageContext"
        },
        {
            "descriptor": "(Ljava/lang/String;)Ljava/lang/Class;",
            "class": "Ljava/lang/ClassLoader;",
            "method": "loadClass"
        }
    ],
    "score": 1,
    "label": []
}
```

## Quark Script Result

```TEXT
$ python3 CWE-94.py
Method: checkSignatures not found!
CWE-94 is detected in ovaa.apk
```
