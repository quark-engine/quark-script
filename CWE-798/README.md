# Detect CWE-798 in Android Application (ovaa.apk)

This scenario seeks to find hard-coded credentials in the APK file. See [CWE-798](https://cwe.mitre.org/data/definitions/798.html) for more details.

Let’s use this [APK](https://github.com/oversecured/ovaa) and the above APIs to show how Quark script find this vulnerability.

First, we design a detection rule `findSecretKeySpec.json` to spot on behavior uses method `SecretKeySpec`. Then, we get all the parameter values that input to this method. From the returned parameter values, we identify it’s a AES key and parse the key out of the values. Finally, we dump all strings in the APK file and check if the AES key is in the strings. If the answer is YES, BINGO!!! We find hard-coded credentials in the APK file.
## Quark Scipt: CWE-798.py
```python
import re
from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "ovaa.apk"
RULE_PATH = "findSecretKeySpec.json"

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for secretKeySpec in quarkResult.behaviorOccurList:

    allStrings = quarkResult.getAllStrings()

    firstParam = secretKeySpec.getParamValues()[1]
    secondParam = secretKeySpec.getParamValues()[2]

    if secondParam == "AES":
        AESKey = re.findall(r'\((.*?)\)', firstParam)[1]

    if AESKey in allStrings:
        print(f"Found hard-coded {secondParam} key {AESKey}")
```

## Quark Rule: findSecretKeySpec.json
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
```
$ python3 findSecretKeySpec.py

Found hard-coded AES key 49u5gh249gh24985ghf429gh4ch8f23f
```



## Hard-Coded AES key in the APK file
```
const-string v2, "49u5gh249gh24985ghf429gh4ch8f23f"

invoke-virtual {v2}, Ljava/lang/String;->getBytes()[B

move-result-object v2

invoke-direct {v1, v2, v0}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
```
