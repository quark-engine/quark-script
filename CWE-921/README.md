# Detect CWE-921 in Android Application

This scenario seeks to find the **unsecured storage mechanism of sensitive data** in the APK file.

## CWE-921: Storage of Sensitive Data in a Mechanism without Access Control

We analyze the definition of CWE-921 and identify its characteristics.

See [CWE-921](https://cwe.mitre.org/data/definitions/921.html) for more details.

![image](https://imgur.com/2zlPLHe.jpg)


## Code of CWE-921 in ovaa.apk

We use the [ovaa.apk](https://github.com/oversecured/ovaa) sample to explain the vulnerability code of CWE-921.

![image](https://imgur.com/2u5iL1K.jpg)

## CWE-921 Detection Process Using Quark Script API

![image](https://imgur.com/qHOMqKy.jpg)

Let’s use the above APIs to show how the Quark script finds this vulnerability.

First, we design a detection rule ``checkFileExistence.json`` to spot on behavior that checks if a file exists on a given storage mechanism. Then, we use API ``methodInstance.getArguments()`` to get the file path. Finally, CWE-921 is found if the file path contains the keyword ``sdcard``.

## Quark Script: CWE-921.py

![image](https://imgur.com/HULgyIy.jpg)

```python
from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "ovaa.apk"
RULE_PATH = "checkFileExistence.json"

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for existingFile in quarkResult.behaviorOccurList:
    filePath = existingFile.secondAPI.getArguments()[0]
    if "sdcard" in filePath:
        print(f"This file is stored inside the SDcard\n")
        print(f"CWE-921 is detected in {SAMPLE_PATH}.")
```

## Quark Rule: checkFileExistence.json

![image](https://imgur.com/zRiYLtS.jpg)

```json
{
    "crime": "Check file existence",
    "permission": [],
    "api": [
        {
            "descriptor": "(Ljava/lang/String;)V",
            "class": "Ljava/io/File;",
            "method": "<init>"
        },
        {
            "descriptor": "()Z",
            "class": "Ljava/io/File;",
            "method": "exists"
        }
    ],
    "score": 1,
    "label": []
}
```

## Quark Script Result

```
$ python3 CWE-921.py
This file is stored inside the SDcard

CWE-921 is detected in ovaa.apk.
```
