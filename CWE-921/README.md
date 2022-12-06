# Detect CWE-921 in Android Application (ovaa.apk)

This scenario seeks to find unsecure storage mechanism of data in the APK file. See [CWE-921](https://cwe.mitre.org/data/definitions/921.html) for more details.

Let’s use this [APK](https://github.com/oversecured/ovaa) and the above APIs to show how Quark script find this vulnerability.

First, we design a detection rule `checkFileExistence.json` to spot on behavior that checks if a file exist on given storage mechanism. Then, we use API `getParamValues()` to get the file path. Finally, CWE-921 is found if the file path contains keyword `sdcard`.

## Quark Script CWE-921.py
```python
from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "ovaa.apk"
RULE_PATH = "checkFileExistence.json"

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for existingFile in quarkResult.behaviorOccurList:
    filePath = existingFile.getParamValues()[0]
    if "sdcard" in filePath:
        print(f"This file is stored inside the SDcard\n")
        print(f"CWE-921 is detected in {SAMPLE_PATH}.")
```

## Quark Rule: checkFileExistence.json
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
