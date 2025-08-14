# Detect CWE-940 in Android Application

This scenario seeks to find the **Improper Verification of Source of a Communication Channel** in the APK file.

## CWE-940: Improper Verification of Source of a Communication Channel

We analyze the definition of CWE-940 and identify its characteristics.

See [CWE-940](https://cwe.mitre.org/data/definitions/940.html) for more details.

![image](https://imgur.com/wia3OKo.png)

## Code of CWE-940 in ovaa.apk

We use the [ovaa.apk](https://github.com/oversecured/ovaa) sample to explain the vulnerability code of CWE-940.

![image](https://imgur.com/1zP5xkN.png)

## Quark Script: CWE-940.py

Let’s use the above APIs to show how the Quark script finds this vulnerability.

To begin with, we create a detection rule named `LoadUrlFromIntent.json` to identify behavior that loads URLs from intent data to the `WebView`.

Next, we retrieve the methods that pass the URL. Then, we check if these methods are only for getting the URL, such as `findViewById`, `getStringExtra`, or `getIntent`.

If **YES**, it could imply that the APK uses communication channels without proper verification, which may cause CWE-940 vulnerability.

```python
from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "ovaa.apk"
RULE_PATH = "LoadUrlFromIntent.json"

URL_GETTING_METHODS = [
    "findViewById",
    "getStringExtra",
    "getIntent",
]

ruleInstance = Rule(RULE_PATH)

quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for behaviorInstance in quarkResult.behaviorOccurList:
    methodsInArgs = behaviorInstance.getMethodsInArgs()

    verifiedMethodCandidates = []

    for method in methodsInArgs:
        if method.methodName not in URL_GETTING_METHODS:
            verifiedMethodCandidates.append(method)

    if verifiedMethodCandidates == []:
        caller = behaviorInstance.methodCaller.fullName
        print(f"CWE-940 is detected in method, {caller}")
```

## Quark Rule: LoadUrlFromIntent.json

```
{
    "crime": "Load Url from Intent",
    "permission": [],
    "api": [
        {
            "class": "Landroid/content/Intent;",
            "method": "getStringExtra",
            "descriptor": "(Ljava/lang/String;)Ljava/lang/String"
        },
        {
            "class": "Landroid/webkit/WebView;",
            "method": "loadUrl",
            "descriptor": "(Ljava/lang/String;)V"
        }
    ],
    "score": 1,
    "label": []
}
```

## Quark Script Result

```
$ python CWE-940.py
CWE-940 is detected in method, Loversecured/ovaa/activities/WebViewActivity; onCreate (Landroid/os/Bundle;)V
```
