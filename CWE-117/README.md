# Detect CWE-117 in Android Application

This scenario seeks to find **Improper Output Neutralization for Logs**.

## CWE-117: Improper Output Neutralization for Logs

We analyze the definition of CWE-117 and identify its characteristics.

See [CWE-117](https://cwe.mitre.org/data/definitions/117.html) for more details.

![image](https://imgur.com/JEAyEsU.jpg)

## Code of CWE-117 in allsafe.apk

We use the [allsafe.apk](https://github.com/t0thkr1s/allsafe) sample to explain the vulnerability code of CWE-117.

![image](https://imgur.com/ueePFNu.jpg)

## CWE-117 Detection Process Using Quark Script API

![image](https://imgur.com/Y5hd4Uc.jpg)

First, we design a detection rule ``writeContentToLog.json`` to spot on behavior using the method that writes contents to the log file.

Then, we use ``methodInstance.getArguments()`` to get all parameter values of this method. And we check if these parameters contain keywords of APIs for neutralization, such as ``escape``, ``replace``, ``format``, and ``setFilter``.

If the answer is **YES**, that may result in secret context leakage into the log file, or the attacker may perform log forging attacks.

## Quark Script CWE-117.py

![image](https://imgur.com/F1X3qg3.jpg)

```python
from quark.script import Rule, runQuarkAnalysis

SAMPLE_PATH = "allsafe.apk"
RULE_PATH = "writeContentToLog.json"
KEYWORDS_FOR_NEUTRALIZATION = ["escape", "replace", "format", "setFilter"]

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for logOutputBehavior in quarkResult.behaviorOccurList:

    secondAPIParam = logOutputBehavior.secondAPI.getArguments()

    isKeywordFound = False
    for keyword in KEYWORDS_FOR_NEUTRALIZATION:
        if keyword in secondAPIParam:
            isKeywordFound = True
            break

    if not isKeywordFound:
        caller = logOutputBehavior.methodCaller.fullName
        print(f"CWE-117 is detected in method, {caller}")
```

## Quark Rule: writeContentToLog.json

![image](https://imgur.com/hC4zGgT.jpg)

```json
{
    "crime": "Write contents to the log",
    "permission": [],
    "api": [
        {
            "descriptor": "()Landroid/text/Editable;",
            "class": "Lcom/google/android/material/textfield/TextInputEditText;",
            "method": "getText"
        },
        {
            "descriptor": "(Ljava/lang/String;Ljava/lang/String;)I",
            "class": "Landroid/util/Log;",
            "method": "d"
        }
    ],
    "score": 1,
    "label": []
}
```

## Quark Script Result

```TEXT
$ python CWE-117.py
CWE-117 is detected in method, Linfosecadventures/allsafe/challenges/InsecureLogging; lambda$onCreateView$0 (Lcom/google/android/material/textfield/TextInputEditText; Landroid/widget/TextView; I Landroid/view/KeyEvent;)Z
```