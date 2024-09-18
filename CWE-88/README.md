# Detect CWE-88 in Android Application


This scenario seeks to find **Argument Injection** in the APK file.

## CWE-88 Improper Neutralization of Argument Delimiters in a Command

We analyze the definition of CWE-88 and identify its characteristics.

See [CWE-88](https://cwe.mitre.org/data/definitions/88.html) for more
details.

![image](https://imgur.com/7EBPGUT.png)

## Code of CWE-88 in vuldroid.apk

We use the [vuldroid.apk](https://github.com/jaiswalakshansh/Vuldroid)
sample to explain the vulnerability code of CWE-88.

![image](https://imgur.com/emnvGcE.png)

## Quark Script: CWE-88.py

Let's use the above APIs to show how the Quark script finds this
vulnerability.

First, we design a detection rule `ExternalStringsCommands.json` to spot
on behavior using external strings as commands.

Next, we use Quark API `behaviorInstance.getMethodsInArgs()` to get the
methods that passed the external command.

Then we check if the method neutralizes any special elements in the
argument.

If the neutralization is not complete, then it may cause CWE-88
vulnerability.

``` python
from quark.script import runQuarkAnalysis, Rule, findMethodInAPK

SAMPLE_PATH = "Vuldroid.apk"
RULE_PATH = "ExternalStringCommand.json"


STRING_MATCHING_API = set([
    ("Ljava/lang/String;", "contains", "(Ljava/lang/CharSequence)Z"),
    ("Ljava/lang/String;", "indexOf", "(I)I"),
    ("Ljava/lang/String;", "indexOf", "(Ljava/lang/String;)I"),
    ("Ljava/lang/String;", "matches", "(Ljava/lang/String;)Z"),
    ("Ljava/lang/String;", "replaceAll", "(Ljava/lang/String; Ljava/lang/String;)Ljava/lang/String;")
])

delimeter = "-"

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for ExternalStringCommand in quarkResult.behaviorOccurList:

    methodCalled = set()
    caller = ExternalStringCommand.methodCaller

    for method in ExternalStringCommand.getMethodsInArgs():
        methodCalled.add(method.fullName)

    if methodCalled.intersection(STRING_MATCHING_API) and not ExternalStringCommand.hasString(delimeter):
        continue
    else:
        print(f"CWE-88 is detected in method, {caller.fullName}")
```

## Quark Rule: ExternalStringCommand.json

``` json
{
    "crime": "Using external strings as commands",
    "permission": [],
    "api": [
        {
            "class": "Landroid/content/Intent;",
            "method": "getStringExtra",
            "descriptor": "(Ljava/lang/String;)Ljava/lang/String"
        },
        {
            "class": "Ljava/lang/Runtime;",
            "method": "exec",
            "descriptor": "(Ljava/lang/String;)Ljava/lang/Process"
        }
    ],
    "score": 1,
    "label": []
}
```

## Quark Script Result

``` TEXT
$ python3 CWE-88.py
CWE-88 is detected in method, Lcom/vuldroid/application/RootDetection; onCreate (Landroid/os/Bundle;)V
```
