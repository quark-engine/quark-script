# Detect CWE-338 in Android Application

This scenario seeks to find **Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)**.

## CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)

We analyze the definition of CWE-338 and identify its characteristics.

See [CWE-338](https://cwe.mitre.org/data/definitions/338.html) for more details.

![image](https://imgur.com/aLybax5.jpg)

## Code of CWE-338 in pivaa.apk

We use the [pivaa.apk](https://github.com/HTBridge/pivaa) sample to explain the vulnerability code of CWE-338.

![image](https://i.postimg.cc/mr5rpTDz/image.png)

## CWE-338 Detection Process Using Quark Script API

![image](https://imgur.com/yWLNwZV.jpg)

First, we design a detection rule `useMethodOfPRNG.json` to spot on behavior that uses Pseudo Random Number Generator (PRNG). Then, we use API `methodInstance.getXrefFrom()` to get the caller method of PRNG. Finally, we use some keywords such as "token", "password", and "encrypt" to check if the PRNG is for credential usage.

## Quark Script CWE-338.py

![image](https://i.postimg.cc/xdt54Lft/image.png)

```python
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
        if any(
            keyword in prngCaller.fullName for keyword in CREDENTIAL_KEYWORDS
        ):
            print("CWE-338 is detected in %s" % prngCaller.fullName)
```
    
## Quark Rule: useMethodOfPRNG.json

![image](https://i.postimg.cc/jS6x74Kg/image.png)

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
