# Detect CWE-502 in Android Application


This scenario seeks to find **Deserialization of Untrusted Data** in the
APK file.

## CWE-502: Deserialization of Untrusted Data

We analyze the definition of CWE-502 and identify its characteristics.

See [CWE-502](https://cwe.mitre.org/data/definitions/502.html) for more
details.

![image](https://imgur.com/Zee9kcJ.jpg)

## Code of CWE-502 in pivaa.apk

We use the [pivaa.apk](https://github.com/htbridge/pivaa) sample to
explain the vulnerability code of CWE-502.

![image](https://imgur.com/yZl5XS3.jpg)

## Quark Script CWE-502.py

Let's use the above APIs to show how the Quark script finds this
vulnerability.

To begin with, we created a detection rule named `deserializeData.json`
to identify behaviors that deserialize data.

Next, we retrieve the methods that interact with the deserialization
API. Following this, we check if there are any of the APIs in
`verificationApis` are found.

If **NO**, it could imply that the APK deserializes the untrusted data,
potentially leading to a CWE-502 vulnerability.

``` python
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

``` json
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

-   **pivaa.apk**

``` TEXT
$ python CWE-502.py
CWE-502 is detected in method, Lcom/htbridge/pivaa/handlers/ObjectSerialization; loadObject ()V
```
