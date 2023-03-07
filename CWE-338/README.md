# Detect CWE-338 in Android Application (pivva.apk)

This scenario aims to detect the **Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG).** See [CWE-338](https://cwe.mitre.org/data/definitions/338.html) for more details.

To demonstrate how the Quark script finds this vulnerability, we will use the [pivaa](https://github.com/HTBridge/pivaa) APK file and the above APIs.

First, we design a detection rule useMethodOfPRNG.json to spot on behavior that uses Pseudo Random Number Generator (PRNG). Then, we use API `getXrefFrom()` to get the caller method of PRNG. Finally, we use some keywords such as “token”, “password”, and “encrypt” to check if the PRNG is for credential usage.

## Quark Script CWE-338.py

``` python
from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "pivaa.apk"
RULE_PATH = "useMethodOfPRNG.json"

CREDENTIAL_KEYWORDS = [
    "token", "password", "account", "encrypt",
    "authentication", "authorization", "id", "key"
]

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for usePRNGMethod in quarkResult.behaviorOccurList:
    for prngCaller in usePRNGMethod.methodCaller.getXrefFrom():
        if any(keyword in prngCaller.fullName
               for keyword in CREDENTIAL_KEYWORDS):
            print("CWE-338 is detected in %s" % prngCaller.fullName)

```

## useMethodOfPRNG.json

```json
{
    "crime": "Use method of PRNG",
    "permission": [],
    "api": [
        {
            "class": "Ljava/util/Random;",
            "method": "<init>",
            "descriptor": "()V"
        },
        {
            "class": "Ljava/util/Random;",
            "method": "nextInt",
            "descriptor": "(I)I"
        }
    ],
    "score": 1,
    "label": []
}
```

## Quark Script Result

```TEXT
$ python CWE-338.py  
CWE-338 is detected in Lcom/htbridge/pivaa/EncryptionActivity$2; onClick (Landroid/view/View;)V
```
