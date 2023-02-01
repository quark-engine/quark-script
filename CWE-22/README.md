# Detect CWE-22 in Android Application (ovaa.apk and InsecureBankv2.apk )

This scenario seeks to find **the improper limitation of a pathname to a restricted directory ('Path Traversal')**. See [CWE-22](https://cwe.mitre.org/data/definitions/22.html) for more details.

Let’s use [ovaa.apk](https://github.com/oversecured/ovaa), [InsecureBankv2.apk](https://github.com/dineshshetty/Android-InsecureBankv2/releases), and the above APIs to show how the Quark script finds this vulnerability.

First, we design a detection rule `accessFileInExternalDir.json` to spot behavior accessing a file in an external directory.

Next, we use API `methodInstance.getArguments()` to get the argument for the file path and use `quarkResultInstance.isHardcoded(argument)` to check if the argument is hardcoded into the APK. If **No**, the argument is from external input.

Finally, we use Quark API `quarkResultInstance.findMethodInCaller(callerMethod, targetMethod)` to check if there are any APIs in the caller method for string matching. If NO, the APK does not neutralize special elements within the argument, which may cause CWE-22 vulnerability.

## Quark Script CWE-22.py
The Quark Script below uses ovaa.apk to demonstrate. You can change the `SAMPLE_PATH` to the sample you want to detect. For example, `SAMPLE_PATH = InsecureBankv2.apk`.

```python
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
            api for api in STRING_MATCHING_API if quarkResult.findMethodInCaller(
                caller, api)
    ]

    if not strMatchingAPIs:
        print(f"CWE-22 is detected in method, {caller.fullName}")
```


## Quark Rule: accessFileInExternalDir.json
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
+ **ovaa.apk**
```
$ python3 CWE-22.py
CWE-22 is detected in method, Loversecured/ovaa/providers/TheftOverwriteProvider; openFile (Landroid/net/Uri; Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;
```

+ **InsecureBankv2.apk**
```
$ python3 CWE-22.py
CWE-22 is detected in method, Lcom/android/insecurebankv2/ViewStatement; onCreate (Landroid/os/Bundle;)V
```
