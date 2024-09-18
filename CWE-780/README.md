# Detect CWE-780 in Android Application


This scenario seeks to find **the use of the RSA algorithm without
Optimal Asymmetric Encryption Padding (OAEP)** in the APK file.

## CWE-780 Use of RSA Algorithm without OAEP

We analyze the definition of CWE-780 and identify its characteristics.

See [CWE-780](https://cwe.mitre.org/data/definitions/780.html) for more
details.

![image](https://imgur.com/veZNZcg.png)

## Code of CWE-780 in dvba.apk

We use the
[MSTG-Android-Java.apk](https://github.com/OWASP/MASTG-Hacking-Playground)
sample to explain the vulnerability code of CWE-780.

![image](https://imgur.com/c03senv.png)

## Quark Script: CWE-780.py

Let's use the above APIs to show how the Quark script finds this
vulnerability.

We first design a detection rule `useOfCryptographicAlgo.json` to spot
on behavior using the cryptographic algorithm. Then, we use API
`behaviorInstance.hasString(pattern, isRegex)` to filter behaviors using
the RSA algorithm. Finally, we use the same API to check if the
algorithm runs without the OAEP scheme. If the answer is YES, the
plaintext is predictable.

``` python
from quark.script import Rule, runQuarkAnalysis

SAMPLE_PATH = "MSTG-Android-Java.apk"
RULE_PATH = "useOfCryptographicAlgo.json"

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for useCryptographicAlgo in quarkResult.behaviorOccurList:
    methodCaller = useCryptographicAlgo.methodCaller

    if useCryptographicAlgo.hasString(
        "RSA"
    ) and not useCryptographicAlgo.hasString("OAEP"):
        print(f"CWE-780 is detected in method, {methodCaller.fullName}")
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
            "descriptor": "(Ljava/lang/String; Ljava/lang/String;)Ljavax/crypto/Cipher"
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
$ python3 CWE-780.py
CWE-780 is detected in method, Lsg/vp/owasp_mobile/OMTG_Android/OMTG_DATAST_001_KeyStore; encryptString (Ljava/lang/String;)V
```
