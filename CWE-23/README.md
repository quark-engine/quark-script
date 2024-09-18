# Detect CWE-23 in Android Application

This scenario aims to demonstrate the detection of the **Relative Path
Traversal** vulnerability.

## CWE-23: Relative Path Traversal

We analyze the definition of CWE-23 and identify its characteristics.

See [CWE-23](https://cwe.mitre.org/data/definitions/23.html) for more
details.

![image](https://imgur.com/YS9umQp.png)

## Code of CWE-23 in ovaa.apk

We use the [ovaa.apk](https://github.com/oversecured/ovaa) sample to
explain the vulnerability code of CWE-23.

![image](https://imgur.com/GosANyj.png)

## Quark Script: CWE-23.py

Let's use the above APIs to show how the Quark script finds this
vulnerability.

To begin with, we will create a detection rule named
`accessFileInExternalDir.json` to identify behavior that accesses a file
in an external directory.

Next, we will use `methodInstance.getArguments()` to retrieve the file
path argument and check whether it belongs to the APK or not. If it does
not belong to the APK, the argument is likely from external input.

Finally, we will use the Quark API
`quarkResultInstance.findMethodInCaller(callerMethod, targetMethod)` to
search for any APIs in the caller method that match the string. If no
matching API is found, the APK does not neutralize special elements
within the argument, which may result in the CWE-23 vulnerability. If a
matching API is found, we will verify whether it neutralizes the
Relative Path string or not. If it does not neutralize it, the APK may
still be vulnerable to CWE-23.

``` python
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
    elif strMatchingAPIs.find("..") == -1:
        print(f"CWE-23 is detected in method, {caller.fullName}")
```

## Quark Rule: accessFileInExternalDir.json

``` json
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

``` TEXT
$ python3 CWE-23.py
CWE-23 is detected in method, Loversecured/ovaa/providers/TheftOverwriteProvider; openFile (Landroid/net/Uri; Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;
```
