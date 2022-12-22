# Detect CWE-79 in Android Application (Vuldroid.apk)

This scenario seeks to find **Improper Neutralization of Input During Web Page Generation (‘Cross-site Scripting’).** See [CWE-79](https://cwe.mitre.org/data/definitions/79.html) for more details.

Let’s use this [APK](https://github.com/jaiswalakshansh/Vuldroid) and the above APIs to show how the Quark script finds this vulnerability.

First, we design a detection rule `loadUrlFromIntent.json` to spot on behavior loading URL from intent data to the WebView instance.

Next, we use API `quarkResultInstance.findMethodInCaller(callerMethod, targetMethod)` and `methodInstance.getArguments()` to check if the Javascript execution is enabled in the WebView. Finally, we check if there are any famous XSS filters. If **NO**, that may cause CWE-79 vulnerability.

### Quark Script CWE-79.py

```python

from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "Vuldroid.apk"
RULE_PATH = "loadUrlFromIntent.json"

XSS_FILTERS = [
    [
        "Lorg/owasp/esapi/Validator;", "getValidSafeHTML",
        "(Ljava/lang/String; Ljava/lang/String; I Z)Ljava/lang/String;",
    ],
    [
        "Lorg/owasp/esapi/Encoder;", "encodeForHTML",
        "(Ljava/lang/String;)Ljava/lang/String;",
    ],
    [
        "Lorg/owasp/esapi/Encoder;", "encodeForJavaScript",
        "(Ljava/lang/String;)Ljava/lang/String;",
    ],
    [
        "Lorg/owasp/html/PolicyFactory;", "sanitize",
        "(Ljava/lang/String;)Ljava/lang/String;",
    ],
]

targetMethod = [
    "Landroid/webkit/WebSettings;", "setJavaScriptEnabled",
    "(Z)V"
]

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for loadUrl in quarkResult.behaviorOccurList:
    caller = loadUrl.methodCaller
    setJS = quarkResult.findMethodInCaller(caller, targetMethod)
    enableJS = []

    if setJS:
        enableJS = setJS[0].getArguments()[1]

    if enableJS:
        XSSFiltersInCaller = [
            filterAPI for filterAPI in XSS_FILTERS if quarkResult.findMethodInCaller(caller, filterAPI)
        ]

        if not XSSFiltersInCaller:
            print(f"CWE-79 is detected in method, {caller.fullName}")

```

### Quark Rule: loadUrlFromIntent.json

```json
{
    "crime": "Load URL from intent to WebView",
    "permission": [],
    "api": [
        {
            "descriptor": "()Landroid/net/Uri;",
            "class": "Landroid/content/Intent;",
            "method": "getData"
        },
        {
            "descriptor": "(Ljava/lang/String;)V",
            "class": "Landroid/webkit/WebView;",
            "method": "loadUrl"
        }
    ],
    "score": 1,
    "label": []
}
```


### Quark Script Result

```
$ python CWE-79.py
CWE-79 is detected in method, Lcom/vuldroid/application/ForgetPassword; onCreate (Landroid/os/Bundle;)V
```
