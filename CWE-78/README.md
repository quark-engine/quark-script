# Detect CWE-78 in Android Application

This scenario seeks to find **Improper Neutralization of Special Elements used in an OS Command** in the APK file.

## CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

We analyze the definition of CWE-78 and identify its characteristics.

See [CWE-78](https://cwe.mitre.org/data/definitions/78.html) for more details.

![image](https://imgur.com/HpMGGsO.png)

## Code of CWE-78 in Vuldroid.apk

We use the [Vuldroid.apk](https://github.com/jaiswalakshansh/Vuldroid) sample to explain the vulnerability code of CWE-78.

![image](https://imgur.com/7Tu0Y3H.png)

## CWE-78 Detection Process Using Quark Script API

![image](https://imgur.com/Hi7qGjw.png)

Let’s use the above APIs to show how the Quark script finds this vulnerability.

First, we design a detection rule `ExternalStringsCommands.json` to spot on behavior using external strings as commands.

Next, we use Quark API `behaviorInstance.getMethodsInArgs()` to get the methods that passed the external command.

Then we check if the method neutralizes any special elements in the argument.

If the neutralization is not complete, then it may cause CWE-78 vulnerability.

## Quark Script: CWE-78.py

![image](https://imgur.com/UpRWgGe.png)

```python
from quark.script import runQuarkAnalysis, Rule, findMethodInAPK

SAMPLE_PATH = "Vuldroid.apk"
RULE_PATH = "ExternalStringCommand.json"


STRING_MATCHING_API = set([
    ("Ljava/lang/String;", "contains", "(Ljava/lang/CharSequence)Z"),
    ("Ljava/lang/String;", "indexOf", "(I)I"),
    ("Ljava/lang/String;", "indexOf", "(Ljava/lang/String;)I"),
    ("Ljava/lang/String;", "matches", "(Ljava/lang/String;)Z"),
    (
        "Ljava/lang/String;",
        "replaceAll",
        "(Ljava/lang/String; Ljava/lang/String;)Ljava/lang/String;",
    ),
])

specialElementsPattern = r"[ ;|,>`]+"

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for ExternalStringCommand in quarkResult.behaviorOccurList:

    methodCalled = set()
    caller = ExternalStringCommand.methodCaller

    for method in ExternalStringCommand.getMethodsInArgs():
        methodCalled.add(method.fullName)

    if methodCalled.intersection(STRING_MATCHING_API) and not ExternalStringCommand.hasString(specialElementsPattern):
        continue
    else:
        print(f"CWE-78 is detected in method, {caller.fullName}")
```
        
## Quark Rule: ExternalStringCommand.json

![image](https://imgur.com/eoV8hnZ.png)

```json
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

```
$ python3 CWE-78.py
CWE-78 is detected in method, Lcom/vuldroid/application/RootDetection; onCreate (Landroid/os/Bundle;)V
```
