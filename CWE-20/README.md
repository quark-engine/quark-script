# Detect CWE-20 in Android Application


This scenario seeks to find **Improper Input Validation** in the APK
file.

## CWE-20 Improper Input Validation

We analyze the definition of CWE-20 and identify its characteristics.

See [CWE-20](https://cwe.mitre.org/data/definitions/20.html) for more
details.

![image](https://imgur.com/21CzFUq.jpg)

## Code of CWE-20 in diva.apk

We use the [diva.apk](https://github.com/payatu/diva-android) sample to
explain the vulnerability code of CWE-20.

![image](https://imgur.com/kRIuEHd.jpg)

## Quark Script CWE-20.py

Let's use the above APIs to show how the Quark script finds this
vulnerability.

First, we design a detection rule `openUrlThatUserInput.json`, to spot
the behavior of opening the URL that the user inputs. Then, we use API
`behaviorInstance.getMethodsInArgs()` to get a list of methods that the
URL in `loadUrl` passes through. Finally, we check if any validation
method is in the list. If No, the APK does not validate user input. That
causes CWE-20 vulnerability.

``` python
from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "diva.apk"
RULE_PATH = "openUrlThatUserInput.json"

rule = Rule(RULE_PATH)
result = runQuarkAnalysis(SAMPLE_PATH, rule)

VALIDATE_METHODS = ["contains", "indexOf", "matches", "replaceAll"]

for openUrl in result.behaviorOccurList:
    calledMethods = openUrl.getMethodsInArgs()

    if not any(
        method.methodName in VALIDATE_METHODS for method in calledMethods
    ):
        print(f"CWE-20 is detected in method, {openUrl.methodCaller.fullName}")
```

## Quark Rule: openUrlThatUserInput.json

``` json
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

``` TEXT
$ python CWE-20.py
CWE-20 is detected in method, Ljakhar/aseem/diva/InputValidation2URISchemeActivity; get (Landroid/view/View;)V
```
