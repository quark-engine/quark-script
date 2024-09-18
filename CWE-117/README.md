# Detect CWE-117 in Android Application (allsafe.apk)


This scenario seeks to find **Improper Output Neutralization for Logs**.
See [CWE-117](https://cwe.mitre.org/data/definitions/117.html) for more
details.

Let's use this [APK](https://github.com/t0thkr1s/allsafe) and the above
APIs to show how the Quark script finds this vulnerability.

First, we design a detection rule `writeContentToLog.json` to spot on
behavior using the method that writes contents to the log file.

Then, we use `methodInstance.getArguments()` to get all parameter values
of this method. And we check if these parameters contain keywords of
APIs for neutralization, such as `escape`, `replace`, `format`, and
`setFilter`.

If the answer is **YES**, that may result in secret context leakage into
the log file, or the attacker may perform log forging attacks.

## Quark Script CWE-117.py

``` python
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

``` json
{
    "crime": "Write contents to the log.",
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

-   **allsafe.apk**

``` TEXT
$ python CWE-117.py
CWE-117 is detected in method, Linfosecadventures/allsafe/challenges/InsecureLogging; lambda$onCreateView$0 (Lcom/google/android/material/textfield/TextInputEditText; Landroid/widget/TextView; I Landroid/view/KeyEvent;)Z
```
