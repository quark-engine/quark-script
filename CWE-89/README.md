# Detect CWE-89 in Android Application

This scenario seeks to find **SQL injection** in the APK file.

## CWE-89 Improper Neutralization of Special Elements used in an SQL Command

We analyze the definition of CWE-89 and identify its characteristics.

See [CWE-89](https://cwe.mitre.org/data/definitions/89.html) for more
details.

![image](https://i.imgur.com/iJ1yIBb.jpg)

## Code of CWE-89 in androgoat.apk

We use the [androgoat.apk](https://github.com/satishpatnayak/AndroGoat)
sample to explain the vulnerability code of CWE-89.

![image](https://i.imgur.com/bdQqWFb.jpg)

## Quark Script: CWE-89.py

Let\'s use the above APIs to show how the Quark script finds this
vulnerability.

First, we design a detection rule `executeSQLCommand.json` to spot on
behavior using SQL command Execution. Then, we use API
`behaviorInstance.isArgFromMethod(targetMethod)` to check if `append`
uses the value of `getText` as the argument. If yes, we confirmed that
the SQL command string is built from user input, which will cause CWE-89
vulnerability.

``` python
from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "AndroGoat.apk"
RULE_PATH = "executeSQLCommand.json"

targetMethod = [
    "Landroid/widget/EditText;", # class name
    "getText",                   # method name
    "()Landroid/text/Editable;", # descriptor
]

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for sqlCommandExecution in quarkResult.behaviorOccurList:
    if sqlCommandExecution.isArgFromMethod(
        targetMethod
    ):
        print(f"CWE-89 is detected in {SAMPLE_PATH}")
```

## Quark Rule: executeSQLCommand.json

``` json
{
    "crime": "Execute SQL Command",
    "permission": [],
    "api": [
        {
            "class": "Ljava/lang/StringBuilder;",
            "method": "append",
            "descriptor": "(Ljava/lang/String;)Ljava/lang/StringBuilder;"
        },
        {
            "class": "Landroid/database/sqlite/SQLiteDatabase;",
            "method": "rawQuery",
            "descriptor": "(Ljava/lang/String; [Ljava/lang/String;)Landroid/database/Cursor;"
        }
    ],
    "score": 1,
    "label": []
}
```

## Quark Script Result

``` text
$ python3 CWE-89.py

CWE-89 is detected in AndroGoat.apk
```
