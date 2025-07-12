# Detect CWE-329 in Android Application


This scenario seeks to find **Generation of Predictable IV with CBC Mode** in the APK file.

## CWE-329: Generation of Predictable IV with CBC Mode


We analyze the definition of CWE-329 and identify its characteristics.

See [CWE-329](https://cwe.mitre.org/data/definitions/329.html) for more details.

![](https://i.postimg.cc/ZY6WjB5z/Screenshot-2025-07-11-17-13-40.png)

## Code of CWE-329 in InsecureBankv2.apk


We use the [InsecureBankv2.apk](https://github.com/dineshshetty/Android-InsecureBankv2) sample to explain the vulnerability code of CWE-329.

![](https://i.postimg.cc/LXgBX9SB/Screenshot-2025-07-11-17-46-25.png)

## CWE-329 Detection Process Using Quark Script API


![](https://i.postimg.cc/50cscyh2/Screenshot-2025-07-12-10-02-34.png)

Let’s use the above APIs to show how the Quark script finds this vulnerability.

To begin with, we created a detection rule named ``initializeCipherWithIV.json`` to identify behaviors that initialize a cipher object with IV. Then, we use API `behaviorInstance.getParamValues()` to check if the cipher object uses CBC mode.

Finally, we use API ``behaviorInstance.isArgFromMethod(targetMethod)``  to check if any random API is applied on the IV used in the cipher object. If **NO**, it could imply that the APK uses a predictable IV in CBC mode cipher, potentially leading to a CWE-329 vulnerability.

## Quark Script CWE-329.py

![](https://i.postimg.cc/prCCnZpm/Screenshot-2025-07-12-10-02-58.png)

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
    cipherName = initCipherWithIV.getParamValues()[0]

    if "CBC" not in cipherName:
        break

    if not any(
        initCipherWithIV.isArgFromMethod(api) for api in randomAPIs
    ):
        print(f"CWE-329 is detected in method, {methodcaller.fullName}")
```
            
## Quark Rule: initializeCipherWithIV.json

![](https://i.postimg.cc/Y9tM29YT/Screenshot-2025-07-11-17-49-41.png)

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

```text
$ python CWE-329.py
CWE-329 is detected in method, Lcom/google/android/gms/internal/zzar; zzc ([B Ljava/lang/String;)[B
CWE-329 is detected in method, Lcom/android/insecurebankv2/CryptoClass; aes256encrypt ([B [B [B)[B
CWE-329 is detected in method, Lcom/android/insecurebankv2/CryptoClass; aes256decrypt ([B [B [B)[B
```


