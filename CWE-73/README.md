# Detect  CWE-73 in Android Application (ovaa.apk)

This scenario seeks to find **External Control of File Name or Path**. See [CWE-73](https://cwe.mitre.org/data/definitions/73.html)  for more details.

First, we design a detection rule `accessFileInExternalDir.json` to spot behavior accessing a file in an external directory.

Second, we use API `methodInstance.getArguments()` to get the argument for the file path and use `quarkResultInstance.isHardcoded(argument)` to check if the argument is hardcoded into the APK. If **No**, the argument is from external input.

Finally, we use Quark API `quarkResultInstance.findMethodInCaller(callerMethod, targetMethod)`  to check if any APIs in the caller method for opening files. If **YES**, the APK performs file operations using external input as a path, which may cause CWE-73 vulnerability.

## Quark Script CWE-73.py
```python
from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "ovaa.apk"
RULE_PATH = "accessFileInExternalDir.json"

OPEN_FILE_API = [
    "Landroid/os/ParcelFileDescriptor;",                   # Class name
    "open",                                                # Method name
    "(Ljava/io/File; I)Landroid/os/ParcelFileDescriptor;"  # Descriptor
]

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for accessExternalDir in quarkResult.behaviorOccurList:
    filePath = accessExternalDir.secondAPI.getArguments()[2]

    if quarkResult.isHardcoded(filePath):
        continue

    caller = accessExternalDir.methodCaller
    result = quarkResult.findMethodInCaller(caller, OPEN_FILE_API)

    if result:
        print("CWE-73 is detected in method, ", caller.fullName)
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
```
$ python CWE-73.py
CWE-73 is detected in method, Loversecured/ovaa/providers/TheftOverwriteProvider; openFile (Landroid/net/Uri; Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;
```
