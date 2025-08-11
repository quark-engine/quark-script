# Detect CWE-24 in Android Application

This scenario aims to demonstrate the detection of the **Relative Path Traversal** vulnerability.

## CWE-24: Path Traversal: '../filedir'

We analyze the definition of CWE-24 and identify its characteristics.

See [CWE-24](https://cwe.mitre.org/data/definitions/24.html) for more details.

![image](https://i.postimg.cc/xdQjd3M2/image.png)

## Code of CWE-24 in ovaa.apk

We use the [ovaa.apk](https://github.com/oversecured/ovaa) sample to explain the vulnerability code of CWE-24.

![image](https://imgur.com/KT277GG.png)

## CWE-24 Detection Process Using Quark Script API

![image](https://i.postimg.cc/YCz0YPp9/image.png)

Let’s use the above APIs to show how the Quark script finds this vulnerability.

To begin with, we create a detection rule named ``accessFileInExternalDir.json`` to identify behavior that accesses a file in an external directory.

Next, we use ``methodInstance.getArguments()`` to retrieve the file path argument and check whether it belongs to the APK. If it does not belong to the APK, the argument is likely from external input.

Finally, we use the Quark Script API ``quarkResultInstance.findMethodInCaller(callerMethod, targetMethod)`` to search for any APIs in the caller method that are used to match strings, and `getParamValues(none)` to retrieve the parameters.

If no API is found or `"../"` is not in the parameters, that implies the APK does not neutralize the special element `../` within the argument, possibly resulting in CWE-24 vulnerability.

## Quark Script: CWE-24.py

![image](https://i.postimg.cc/rwfc82VS/image.png)

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

    if not strMatchingAPIs or "../" not in accessExternalDir.getParamValues():
        print(f"CWE-24 is detected in method, {caller.fullName}")
```

## Quark Rule: accessFileInExternalDir.json

![image](https://i.postimg.cc/1RDQ8qRR/image.png)

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
$ python3 CWE-24.py
CWE-24 is detected in method, Loversecured/ovaa/providers/TheftOverwriteProvider; openFile (Landroid/net/Uri; Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;
```