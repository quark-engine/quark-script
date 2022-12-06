# Detect CWE-780 in Android Application (MSTG-Android-Java.apk)

This scenario seeks to find **the use of the RSA algorithm without Optimal Asymmetric Encryption Padding (OAEP)**. See [CWE-780](https://cwe.mitre.org/data/definitions/780.html) for more details.

Let’s use this [APK](https://github.com/OWASP/MASTG-Hacking-Playground) and the above APIs to show how the Quark script find this vulnerability.

We first design a detection rule `useOfCryptographicAlgo.json` to spot on behavior using the cryptographic algorithm. Then, we use API `behaviorInstance.hasString(pattern, isRegex)` to filter behaviors using the RSA algorithm. Finally, we use the same API to check if the algorithm runs without the OAEP scheme. If the answer is YES, the plaintext is predictable.
## Quark Script CWE-780.py
```python
from quark.script import Rule, runQuarkAnalysis

SAMPLE_PATH = "MSTG-Android-Java.apk"
RULE_PATH = "useOfCryptographicAlgo.json"

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for useCryptographicAlgo in quarkResult.behaviorOccurList:

    methodCaller = useCryptographicAlgo.methodCaller

    if useCryptographicAlgor.hasString("RSA") and \
        not useCryptographicAlgo.hasString("OAEP"):
        print(f"CWE-780 is detected in method, {methodCaller.fullName}")
```

## Quark Rule: useOfCryptographicAlgo.json
```json
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
```
$ python3 CWE-780.py
CWE-780 is detected in method, Lsg/vp/owasp_mobile/OMTG_Android/OMTG_DATAST_001_KeyStore; encryptString (Ljava/lang/String;)V
```
