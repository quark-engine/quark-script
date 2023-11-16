# Detect CWE-502 in Android Application (pivaa)
This scenario aims to demonstrate the detection of the **Deserialization of Untrusted Data** vulnerability using [pivaa.apk](https://github.com/htbridge/pivaa). See [CWE-502](https://cwe.mitre.org/data/definitions/502.html)   for more details.

To begin with, we create a detection rule named ``deserializeData.json`` to identify behaviors that deserialize data.

Next, we retrieve the methods that interact with the deserialization API. Following this, we check if there are any of the APIs in ``verificationApis`` are found.

If **NO**, it could imply that the APK deserializes the untrusted data, potentially leading to a CWE-502 vulnerability.



## Quark Script CWE-502.py
The Quark Script below uses pivaa.apk to demonstrate.

```python
from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "pivaa.apk"
RULE_PATH = "deserializeData.json"

ruleInstance = Rule(RULE_PATH)

result = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

verificationApis = [
    ["Ljava/io/File;", "exists", "()Z"],
    ["Landroid/content/Context;", "getFilesDir", "()Ljava/io/File;"],
    ["Landroid/content/Context;", "getExternalFilesDir", "(Ljava/lang/String;)Ljava/io/File;"],
    ["Landroid/os/Environment;", "getExternalStorageDirectory", "()Ljava/io/File;"],
]

for dataDeserialization in result.behaviorOccurList:
    apis = dataDeserialization.getMethodsInArgs()
    caller = dataDeserialization.methodCaller
    if not any(api in apis for api in verificationApis):
        print(f"CWE-502 is detected in method, {caller.fullName}")
```



## Quark Rule: deserializeData.json
```json

{
    "crime": "Deserialize Data",
    "permission": [],
    "api": [

        {
            "class": "Ljava/io/ObjectInputStream;",
            "method": "<init>",
            "descriptor": "(Ljava/io/InputStream;)V"
        },
        {
            "class": "Ljava/io/ObjectInputStream;",
            "method": "readObject",
            "descriptor": "()Ljava/lang/Object;"
        }  

    ],
    "score": 1,
    "label": []
}
```

## Quark Script Result
- **pivaa.apk**

```
$ python CWE-502.py
CWE-502 is detected in method, Lcom/htbridge/pivaa/handlers/ObjectSerialization; loadObject ()V
```
