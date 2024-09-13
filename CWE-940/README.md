# Detect CWE-940 in Android Application (ovaa,Vuldroid)

This scenario aims to demonstrate the detection of the **Improper
Verification of Source of a Communication Channel** vulnerability using
[ovaa.apk](https://github.com/oversecured/ovaa) and
[Vuldroid.apk](https://github.com/jaiswalakshansh/Vuldroid). See
[CWE-940](https://cwe.mitre.org/data/definitions/940.html) for more
details.

To begin with, we create a detection rule named `LoadUrlFromIntent.json`
to identify behavior that loads url from intent data to the WebView.

Next, we retrieve the methods that pass the url. Following this, we
check if these methods are only for setting intent, such as
`findViewById`, `getStringExtra`, or `getIntent`.

If **NO**, it could imply that the APK uses communication channels
without proper verification, which may cause CWE-940 vulnerability.

# Quark Script CWE-940.py

The Quark Script below uses ovaa.apk to demonstrate. You can change the
`SAMPLE_PATH` to the sample you want to detect. For example,
`SAMPLE_PATH = "Vuldroid.apk"`.

``` python
from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "ovaa.apk"
RULE_PATH = "LoadUrlFromIntent.json"

INTENT_SETTING_METHODS = [
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
        if method.methodName not in INTENT_SETTING_METHODS:
            verifiedMethodCandidates.append(method)

    if verifiedMethodCandidates == []:
        caller = behaviorInstance.methodCaller.fullName
        print(f"cwe-940 is detected in method, {caller}")
```

## Quark Rule: LoadUrlFromIntent.json

``` json
{
    "crime": "Load Url from Intent and open WebView",
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

-   **ovaa.apk**

``` TEXT
$ python CWE-940.py
CWE-940 is detected in method, Loversecured/ovaa/activities/WebViewActivity; onCreate (Landroid/os/Bundle;)V
```
