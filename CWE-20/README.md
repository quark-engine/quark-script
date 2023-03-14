# Detect CWE-20 in Android Application (diva.apk)

This scenario seeks to find Improper Input Validation. See [CWE-20](https://cwe.mitre.org/data/definitions/20.html) for more details.

Let’s use this [APK](https://github.com/payatu/diva-android) and the above APIs to show how the Quark script finds this vulnerability.

First, we design a detection rule `openUrlThatUserInput.json` to spot the behavior of opening the URL that the user input. Then we use API `behaviorInstance.getMethodsInArgs` to get a list of methods which the URL in `loadUrl` has passed through. Finally, we check if any validation method is in the list. If No, the APK does not validate user input. That causes CWE-20 vulnerability.

## Quark Script: CWE-20.py
```python
from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "diva.apk"
RULE_PATH = "openUrlThatUserInput.json"

rule = Rule(RULE_PATH)
result = runQuarkAnalysis(SAMPLE_PATH, rule)

VALIDATE_METHODS = ["contains", "indexOf", "matches", "replaceAll"]

for openUrl in result.behaviorOccurList:
    calledMethods = openUrl.getMethodsInArgs()

    if not any(method.methodName in VALIDATE_METHODS
               for method in calledMethods):
        print("CWE-20 is detected in method,"
              f"{openUrl.methodCaller.fullName}")

```

## Quark Rule: openUrlThatUserInput.json
```json
{
    "crime": "Open the Url that user input",
    "permission": [],
    "api": [
        {
            "class": "Landroid/widget/EditText;",
            "method": "getText",
            "descriptor": "()Landroid/text/Editable;"
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
$ python CWE-20.py
CWE-20 is detected in method, Ljakhar/aseem/diva/InputValidation2URISchemeActivity; get (Landroid/view/View;)V
```
