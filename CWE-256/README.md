# Detect CWE-256 in Android Application

This scenario seeks to find **Plaintext Storage of a Password**.

## CWE-256: Plaintext Storage of a Password

We analyze the definition of CWE-256 and identify its characteristics.

See [CWE-256](https://cwe.mitre.org/data/definitions/256.html) for more details.

![image](https://i.postimg.cc/rpydts5T/image.png)

## Code of CWE-256 in ovaa.apk

We use the [ovaa.apk](https://github.com/oversecured/ovaa) sample to explain the vulnerability code of CWE-256.

![image](https://i.postimg.cc/RhtqzHx7/image.png)

## CWE-256 Detection Process Using Quark Script API

![image](https://i.postimg.cc/X7PzpBFM/image.png)

First, we define a detection rule `putStrAndCommit.json` to identify behaviors that store information using `SharedPreferences.Editor`.

Next, we call `behaviorInstance.getParamValues()` to retrieve all parameter values associated with this behavior. We then check whether any parameter contains keywords that suggest it is being used as a password (e.g., `password`, `pswd`, or `passwd`).

Finally, we use ``behaviorInstance.isArgFromMethod(targetMethod)`` to verify whether the ``doFinal`` method for encryption is applied on the second argument ``value``. (Note: this Quark Script API checks all arguments, not just a specific one. Therefore, the API returns ``True`` even if the ``doFinal`` method is applied on the ``key`` argument rather than the ``value`` argument of ``putString`` . But the situation is so rare that we can neglect it.)

If the answer is **NO**, it indicates that the value may be stored in plaintext, which could lead to a CWE-256 vulnerability.

## Quark Script CWE-256.py

![image](https://i.postimg.cc/brxQ0JNR/image.png)

```python
from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "ovaa.apk"
RULE_PATH = "putStrAndCommit.json"

encryptAPI = ["Ljavax/crypto/Cipher;", "doFinal", ""]

passwordPatterns = ["password", "pswd", "passwd"]


ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for putStrAndCommit in quarkResult.behaviorOccurList:
    paramValues = [
        paramValue.lower() for paramValue in putStrAndCommit.getParamValues()
    ]
    if not any(
        passwordPattern in paramValues for passwordPattern in passwordPatterns
    ):
        continue

    if not putStrAndCommit.isArgFromMethod(encryptAPI):
        print(
            f"CWE-256 is detected in method",
            putStrAndCommit.methodCaller.fullName
        )
```

## Quark Rule: putStrAndCommit.json

![image](https://i.postimg.cc/h4sFPGpg/image.png)

```json
{
    "crime": "Use editor to store information",
    "permission": [],
    "api": [
        {
            "class": "Landroid/content/SharedPreferences$Editor;",
            "method": "putString",
            "descriptor": "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;"
        },
        {
            "class": "Landroid/content/SharedPreferences$Editor;",
            "method": "commit",
            "descriptor": "()Z"
        }
    ],
    "score": 1,
    "label": []
}
```

## Quark Script Result

```TEXT
$ python3 CWE-256.py
CWE-256 is detected in method, Loversecured/ovaa/utils/LoginUtils; saveCredentials (Loversecured/ovaa/objects/LoginData;)V
```