# Detect CWE-23 in Android Application

This scenario aims to demonstrate the detection of the **Relative Path Traversal** vulnerability.

## CWE-23: Relative Path Traversal

We analyze the definition of CWE-23 and identify its characteristics.

See [CWE-23](https://cwe.mitre.org/data/definitions/23.html) for more details.

![image](https://imgur.com/k4UPsKO.png)

## Code of CWE-23 in ovaa.apk

We use the [ovaa.apk](https://github.com/oversecured/ovaa) sample to explain the vulnerability code of CWE-23.

![image](https://imgur.com/KT277GG.png)

## CWE-23 Detection Process Using Quark Script API

![image](https://imgur.com/D852ZLV.png)

Let’s use the above APIs to show how the Quark script finds this vulnerability.

To begin with, we create a detection rule named ``accessFileInExternalDir.json`` to identify behavior that accesses a file in an external directory.

Next, we use ``methodInstance.getArguments()`` to retrieve the file path argument and check whether it belongs to the APK. If it does not belong to the APK, the argument is likely from external input.

Then, we use the Quark Script API ``quarkResultInstance.findMethodInCaller(callerMethod, targetMethod)`` to search for any APIs in the caller method that are used to match strings. If no API is found, that implies the APK does not neutralize special elements within the argument, possibly resulting in CWE-23 vulnerability.

## Quark Script: CWE-23.py

![image](https://imgur.com/lk1C4CX.jpg)

```python
from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "ovaa.apk"
RULE_PATH = "accessFileInExternalDir.json"


STRING_MATCHING_API = [
    ["Ljava/lang/String;", "contains", "(Ljava/lang/CharSequence)Z"],
    ["Ljava/lang/String;", "indexOf", "(I)I"],
    ["Ljava/lang/String;", "indexOf", "(Ljava/lang/String;)I"],
    ["Ljava/lang/String;", "matches", "(Ljava/lang/String;)Z"],
    [
        "Ljava/lang/String;",
        "replaceAll",
        "(Ljava/lang/String; Ljava/lang/String;)Ljava/lang/String;",
    ],
]

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for accessExternalDir in quarkResult.behaviorOccurList:

    filePath = accessExternalDir.secondAPI.getArguments()[2]

    if quarkResult.isHardcoded(filePath):
        continue

    caller = accessExternalDir.methodCaller
    strMatchingAPIs = [
        api
        for api in STRING_MATCHING_API
        if quarkResult.findMethodInCaller(caller, api)
    ]

    if not strMatchingAPIs:
        print(f"CWE-23 is detected in method, {caller.fullName}")
```

## Quark Rule: accessFileInExternalDir.json

![image](https://imgur.com/N2uKsZj.png)

```json
{
    "crime": "Access a file in an external directory",
    "permission": [],
    "api": [
        {
            "class": "Landroid/os/Environment;",
            "method": "getExternalStorageDirectory",
            "descriptor": "()Ljava/io/File;"
        },
        {
            "class": "Ljava/io/File;",
            "method": "<init>",
            "descriptor": "(Ljava/io/File;Ljava/lang/String;)V"
        }
    ],
    "score": 1,
    "label": []
}
```

## Quark Script Result

```
$ python3 CWE-23.py
CWE-23 is detected in method, Loversecured/ovaa/providers/TheftOverwriteProvider; openFile (Landroid/net/Uri; Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;
```