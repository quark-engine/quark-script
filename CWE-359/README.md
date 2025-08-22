# Detect CWE-359 in Android Application

This scenario aims to demonstrate the detection of the **Exposure of Private Personal Information to an Unauthorized Actor** vulnerability.

## CWE-359: Exposure of Private Personal Information to an Unauthorized Actor

We analyze the definition of CWE-359 and identify its characteristics.

See [CWE-359](https://cwe.mitre.org/data/definitions/359.html) for more details.

![image](https://i.postimg.cc/QxZcD3gb/image.png)

## Code of CWE-359 in ovaa.apk

We use the [ovaa.apk](https://github.com/oversecured/ovaa) sample to explain the vulnerability code of CWE-359.

![image](https://i.postimg.cc/LhKL2vvC/image.png)

## CWE-359 Detection Process Using Quark Script API

![image](https://i.postimg.cc/8CB6ywzN/image.png)

Let’s use the above APIs to show how the Quark script finds this vulnerability.

To begin with, we create a detection rule named ``accessFileWithUnsafeUriPath.json`` to identify behavior that accesses a file with an unsafe path from ``Uri``.

Next, we use API ``methodInstance.methodCaller`` to retrieve the name of the caller that has this behavior.

Then, we use API ``quarkResultInstance.isHardcoded(argument)`` to check if the file path is hardcoded into the APK. If not, the file path is likely from external input.

After that, we use API ``getProviders(samplePath)``  and ``providerInstance.isExported()`` to check if there is any exported provider that matches the caller class name. If yes, any external application can access the behavior.

Finally, we use API ``quarkResultInstance.findMethodInCaller(callerMethod, targetMethod)`` to search for any APIs in the caller method that are used to match strings.

If **NO** API is found, that implies the APK does not neutralize special elements within the argument, possibly resulting in a CWE-359 vulnerability.

## Quark Script: CWE-359.py

![image](https://i.postimg.cc/76KT46zR/image.png)

```python
from quark.script import Rule, runQuarkAnalysis, getProviders

SAMPLE_PATH = "ovaa.apk"
RULE_PATH = "accessFileWithUnsafeUriPath.json"

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

exportedProviders = [
    str(provider)
    for provider in getProviders(SAMPLE_PATH)
    if provider.isExported()
]

for behavior in quarkResult.behaviorOccurList:
    caller = behavior.methodCaller
    classNameInJavaFormat = caller.className.replace("/", ".")[1:-1]
    filePath = behavior.secondAPI.getArguments()[2]

    if quarkResult.isHardcoded(filePath):
        continue

    if classNameInJavaFormat not in exportedProviders:
        continue

    if not any(
        quarkResult.findMethodInCaller(caller, api)
        for api in STRING_MATCHING_API
    ):
        print(f"CWE-359 is detected in method, {caller.fullName}")
```

## Quark Rule: accessFileWithUnsafeUriPath.json

![image](https://i.postimg.cc/kGDRgmFg/image.png)

```json
{
    "crime": "Access a File with an unsafe path from Uri",
    "permission": [],
    "api": [
        {
            "class": "Landroid/net/Uri;",
            "method": "getLastPathSegment",
            "descriptor": "()Ljava/lang/String;"
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
$ python3 CWE-359.py
CWE-359 is detected in method, Loversecured/ovaa/providers/TheftOverwriteProvider; openFile (Landroid/net/Uri; Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;
```