# Detect CWE-22 in Android Application

This scenario seeks to find **the improper limitation of a pathname to a
restricted directory ('Path Traversal')**.

## CWE-22: Improper Limitation of a Pathname to a Restricted Directory (\'Path Traversal\')

We analyze the definition of CWE-22 and identify its characteristics.

See [CWE-22](https://cwe.mitre.org/data/definitions/22.html) for more
details.

![image](https://imgur.com/agRPwp8.png)

## Code of CWE-22 in ovaa.apk

We use the [ovaa.apk](https://github.com/oversecured/ovaa) sample to
explain the vulnerability code of CWE-22.

![image](https://imgur.com/WFpfzFk.png)

## Quark Script: CWE-22.py

Let's use the above APIs to show how the Quark script finds this
vulnerability.

First, we design a detection rule `accessFileInExternalDir.json` to spot
behavior accessing a file in an external directory.

Next, we use API `methodInstance.getArguments()` to get the argument for
the file path and use `quarkResultInstance.isHardcoded(argument)` to
check if the argument is hardcoded into the APK. If No, the argument is
from external input.

Finally, we use Quark API
`quarkResultInstance.findMethodInCaller(callerMethod, targetMethod)` to
check if there are any APIs in the caller method for string matching. If
NO, the APK does not neutralize special elements within the argument,
which may cause CWE-22 vulnerability.

``` python
from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "ovaa.apk"
RULE_PATH = "accessFileInExternalDir.json"


STRING_MATCHING_API = [
    ["Ljava/lang/String;", "contains", "(Ljava/lang/CharSequence)Z"],
    ["Ljava/lang/String;", "indexOf", "(I)I"],
    ["Ljava/lang/String;", "indexOf", "(Ljava/lang/String;)I"],
    ["Ljava/lang/String;", "matches", "(Ljava/lang/String;)Z"],
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
        print(f"CWE-22 is detected in method, {caller.fullName}")
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
$ python3 CWE-22.py
CWE-22 is detected in method, Loversecured/ovaa/providers/TheftOverwriteProvider; openFile (Landroid/net/Uri; Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;
```
