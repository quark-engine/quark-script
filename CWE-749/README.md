# Detect CWE-749 in Android Application

This scenario seeks to find **exposed methods or functions** in the APK
file.

## CWE-749 Exposed Dangerous Method or Function

We analyze the definition of CWE-749 and identify its characteristics.

See [CWE-749](https://cwe.mitre.org/data/definitions/749.html) for more
details.

![image](https://imgur.com/hmihGze.png)

## Code of CWE-749 in MSTG-Android-Java.apk

We use the
[MSTG-Android-Java.apk](https://github.com/OWASP/MASTG-Hacking-Playground)
sample to explain the vulnerability code of CWE-749.

![image](https://imgur.com/KiA0vRD.png)

## Quark Script CWE-749.py

Let's use the above APIs to show how the Quark script finds this
vulnerability.

First, we design a detection rule `configureJsExecution.json` to spot on
behavior using the method `setJavascriptEnabled`. Then, we use the API
`methodInstance.getArguments()` to check if it enables JavaScript
execution on websites. Finally, we look for calls to the method
`addJavaScriptInterface` in the caller method. If yes, the APK exposes
dangerous methods or functions to websites. That causes CWE-749
vulnerability.

``` python
from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "MSTG-Android-Java.apk"
RULE_PATH = "configureJsExecution.json"

targetMethod = [
    "Landroid/webkit/WebView;",
    "addJavascriptInterface",
    "(Ljava/lang/Object; Ljava/lang/String;)V"
]

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for configureJsExecution in quarkResult.behaviorOccurList:

    caller = configureJsExecution.methodCaller
    secondAPI = configureJsExecution.secondAPI

    enableJS = secondAPI.getArguments()[1]
    exposeAPI = quarkResult.findMethodInCaller(caller, targetMethod)

    if enableJS and exposeAPI:
        print(f"CWE-749 is detected in method, {caller.fullName}")
```

## Quark Rule: configureJsExecution.json

``` json
{
    "crime": "Configure JavaScript execution on websites",
    "permission": [],
    "api": [
        {
            "class": "Landroid/webkit/WebView;",
            "method": "getSettings",
            "descriptor": "()Landroid/webkit/WebSettings;"
        },
        {
            "class": "Landroid/webkit/WebSettings;",
            "method": "setJavaScriptEnabled",
            "descriptor": "(Z)V"
        }
    ],
    "score": 1,
    "label": []
}
```

## Quark Script Result

``` TEXT
$ python3 CWE-749.py

CWE-749 is detected in method, Lsg/vp/owasp_mobile/OMTG_Android/OMTG_ENV_005_WebView_Remote; onCreate (Landroid/os/Bundle;)V
CWE-749 is detected in method, Lsg/vp/owasp_mobile/OMTG_Android/OMTG_ENV_005_WebView_Local; onCreate (Landroid/os/Bundle;)V
```
