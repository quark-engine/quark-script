# Detect CWE-89 in Android Application (AndroGoat.apk)

This scenario seeks to find SQL injection in the APK file. See [CWE-89](https://cwe.mitre.org/data/definitions/89.html) for more details.

Let’s use this [APK](https://github.com/satishpatnayak/AndroGoat) and the above APIs to show how Quark script find this vulnerability.

First, we design a detection rule executeSQLCommand.json to spot on behavior using SQL command Execution. Then, we use API isArgFromMethod to check if append use the value of getText as the argument. If yes, we confirmed that the SQL command string is built from user input, which will cause CWE-89 vulnerability.
## Quark Script CWE-89.py
```python
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
```json
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

```
$ python3 CWE-89.py

CWE-89 is detected in AndroGoat.apk
```
