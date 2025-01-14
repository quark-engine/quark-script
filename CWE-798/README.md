# Detect CWE-798 in Android Application

This scenario seeks to find **hard-coded credentials** in the APK file.

## CWE-798: Use of Hard-coded Credentials

We analyze the definition of CWE-798 and identify its characteristics.

See [CWE-798](https://cwe.mitre.org/data/definitions/798.html) for more details.

![image](https://imgur.com/rF8J8hE.png)

## Code of CWE-798 in ovaa.apk

We use the [ovaa.apk](https://github.com/oversecured/ovaa) sample to explain the vulnerability code of CWE-798.

![image](https://imgur.com/Cg7DacP.png)


## CWE-798 Detection Process Using Quark Script API

![image](https://imgur.com/R8CfDqD.png)

Let’s use the above APIs to show how the Quark script finds this vulnerability.

First, we design a detection rule ``findSecretKeySpec.json`` to spot on behavior using the constructor ``SecretKeySpec``. Second, we get all the parameter values from this constructor. Then, we parse the AES key from the parameter values. Finally, we check if the AES key is hardcoded in the APK file. If the answer is **YES**, BINGO!!! We find hard-coded credentials in the APK file.

## Quark Script: CWE-798.py

![image](https://imgur.com/IOyrqDc.png)

```python
import re
from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "ovaa.apk"
RULE_PATH = "findSecretKeySpec.json"

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for secretKeySpec in quarkResult.behaviorOccurList:

    firstParam = secretKeySpec.secondAPI.getArguments()[1]
    secondParam = secretKeySpec.secondAPI.getArguments()[2]

    if secondParam == "AES":
        AESKey = re.findall(r"\((.*?)\)", firstParam)[1]

        if quarkResult.isHardcoded(AESKey):
            print(f"Found hard-coded {secondParam} key {AESKey}")
```

## Quark Rule: findSecretKeySpec.json

![image](https://imgur.com/2BYOE70.png)

```json
{
    "crime": "Detect APK using SecretKeySpec.",
    "permission": [],
    "api": [
        {
            "descriptor": "()[B",
            "class": "Ljava/lang/String;",
            "method": "getBytes"
        },
        {
            "descriptor": "([BLjava/lang/String;)V",
            "class": "Ljavax/crypto/spec/SecretKeySpec;",
            "method": "<init>"
        }
    ],
    "score": 1,
    "label": []
}
```

## Quark Script Result

```TEXT
$ python3 CWE-798.py
Found hard-coded AES key 49u5gh249gh24985ghf429gh4ch8f23f
```
