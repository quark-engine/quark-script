# Detect CWE-327 in Android Application

This scenario seeks to find **Use of a Broken or Risky Cryptographic
Algorithm** in the APK file.

# CWE-327 Use of a Broken or Risky Cryptographic Algorithm

We analyze the definition of CWE-327 and identify its characteristics.

See [CWE-327](https://cwe.mitre.org/data/definitions/327.html) for more
details.

![image](https://imgur.com/VlX7MTc.png)

## Code of CWE-327 in InjuredAndroid.apk

We use the [InjuredAndroid.apk](https://github.com/B3nac/InjuredAndroid)
sample to explain the vulnerability code of CWE-327.

![image](https://imgur.com/XFvu8zb.png)

## Quark Script CWE-327.py

Let's use the above APIs to show how the Quark script finds this
vulnerability.

We first design a detection rule `useOfCryptographicAlgo.json` to spot
on behavior using cryptographic algorithms. Then, we use API
`behaviorInstance.hasString(pattern, isRegex)` with a list to check if
the algorithm is risky. If YES, that may cause the exposure of sensitive
data.

``` python
from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "InjuredAndroid.apk"
RULE_PATH = "useOfCryptographicAlgo.json"

WEAK_ALGORITHMS = ["DES", "ARC4", "BLOWFISH"]

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for useCryptoAlgo in quarkResult.behaviorOccurList:

    caller = useCryptoAlgo.methodCaller

    for algo in WEAK_ALGORITHMS:
        if useCryptoAlgo.hasString(algo):
            print(f"CWE-327 is detected in method, {caller.fullName}")
```

## Quark Rule: useOfCryptographicAlgo.json

``` json
{
    "crime": "Use of cryptographic algorithm",
    "permission": [],
    "api": [
        {
            "class": "Ljavax/crypto/Cipher;",
            "method": "getInstance",
            "descriptor": "(Ljava/lang/String;)Ljavax/crypto/Cipher"
        },
        {
            "class": "Ljavax/crypto/Cipher;",
            "method": "init",
            "descriptor": "(I Ljava/security/Key;)V"
        }
    ],
    "score": 1,
    "label": []
}
```

## Quark Script Result

``` TEXT
$ python3 CWE-327.py
CWE-327 is detected in method, Lb3nac/injuredandroid/k; b (Ljava/lang/String;)Ljava/lang/String;
CWE-327 is detected in method, Lb3nac/injuredandroid/k; a (Ljava/lang/String;)Ljava/lang/String;
```
