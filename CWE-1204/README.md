# Detect CWE-1204 in Android Application

This scenario seeks to find **Generation of Weak Initialization Vector (IV)**.

## CWE-1204: Generation of Weak Initialization Vector (IV)

We analyze the definition of CWE-1204 and identify its characteristics.

See [CWE-1204](https://cwe.mitre.org/data/definitions/1204.html) for more details.

![image](https://i.postimg.cc/3NNmYz6J/image.png)

## Code of CWE-1204 in InsecureBankv2.apk

We use the [InsecureBankv2.apk](https://github.com/dineshshetty/Android-InsecureBankv2) sample to explain the vulnerability code of CWE-1204.

![image](https://i.postimg.cc/rsHWmQXG/image.png)


## CWE-1204 Detection Process Using Quark Script API

![image](https://i.postimg.cc/jq3yZdwW/image.png)

Let’s use the above APIs to show how the Quark script finds this vulnerability.

First, we created a detection rule named `initializeCipherWithIV.json` to identify behaviors that initialize a cipher object with IV.

Then, we use API `behaviorInstance.isArgFromMethod(targetMethod)` to check if any random API is applied on the IV used in the cipher object. If **NO**, it could imply that the APK uses a weak IV, potentially leading to a CWE-1204 vulnerability.

## Quark Scipt: CWE-1204.py

![image](https://i.postimg.cc/Hxs79fT4/image.png)

```python
from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "InsecureBankv2.apk"
RULE_PATH = "initializeCipherWithIV.json"

randomAPIs = [
    ["Ljava/security/SecureRandom", "next", "(I)I"],
    ["Ljava/security/SecureRandom", "nextBytes", "([B)V"],
]

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for initCipherWithIV in quarkResult.behaviorOccurList:
    methodcaller = initCipherWithIV.methodCaller

    if not any(
        initCipherWithIV.isArgFromMethod(api) for api in randomAPIs
    ):
        print(f"CWE-1204 is detected in method, {methodcaller.fullName}")
```

## Quark Rule: initializeCipherWithIV.json

![image](https://i.postimg.cc/kGL69GKf/image.png)

```json
{
    "crime": "Initialize a cipher object with IV",
    "permission": [],
    "api": [
        {
            "class": "Ljavax/crypto/spec/IvParameterSpec;",
            "method": "<init>",
            "descriptor": "([B)V"
        },
        {
            "class": "Ljavax/crypto/Cipher;",
            "method": "init",
            "descriptor": "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V"
        }
    ],
    "score": 1,
    "label": []
}
```

## Quark Script Result

```TEXT
$ python CWE-1204.py
CWE-1204 is detected in method, Lcom/android/insecurebankv2/CryptoClass; aes256encrypt ([B [B [B)[B
CWE-1204 is detected in method, Lcom/android/insecurebankv2/CryptoClass; aes256decrypt ([B [B [B)[B
CWE-1204 is detected in method, Lcom/google/android/gms/internal/zzar; zzc ([B Ljava/lang/String;)[B
```