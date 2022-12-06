# Detect CWE-94 in Android Application (ovaa.apk)

This scenario seeks to find code injection in the APK file. See [CWE-94](https://cwe.mitre.org/data/definitions/94.html) for more details.

Let’s use this [APK](https://github.com/oversecured/ovaa) and the above APIs to show how the Quark script finds this vulnerability.

First, we design a detection rule `loadExternalCode.json` to spot on behavior using the method createPackageContext. Then, we find the caller method that calls the createPackageContext. Finally, we check if the method checks signatures are called in the caller method for verification.

## Quark Scipt: CWE-94.py
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
        print(f"\nMethod: {targetMethod[1]} not found!")
        print(f"CWE-94 is detected in {SAMPLE_PATH}")
```

## Quark Rule: loadExternalCode.json
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
```
$ python3 CWE-94.py

Method: checkSignatures not found!
CWE-94 is detected in ovaa.apk
```
