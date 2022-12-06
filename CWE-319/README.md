# Detect CWE-319 in Android Application (ovaa.apk)

This scenario seeks to find **the Cleartext Transmission of Sensitive Information**. See [CWE-319](https://cwe.mitre.org/data/definitions/319.html) for more details.

Let’s use this [APK](https://github.com/oversecured/ovaa) and the above APIs to show how the Quark script finds this vulnerability. This sample uses the package Retrofit to request Web APIs, but the APIs use cleartext protocols.

We first design a detection rule `setRetrofitBaseUrl.json` to spot on behavior that sets the base URL of the Retrofit instance. Then, we loop through a custom list of cleartext protocol schemes and use API `behaviorInstance.hasString` to filter arguments that are URL strings with cleartext protocol.

## Quark Script CWE-319.py
```python
from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "./ovaa.apk"
RULE_PATH = "setRetrofitBaseUrl.json"

PROTOCOL_KEYWORDS = [
    "http",
    "smtp",
    "ftp"
]


ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for setRetrofitBaseUrl in quarkResult.behaviorOccurList:
    for protocol in PROTOCOL_KEYWORDS:

        regexRule = f"{protocol}://[0-9A-Za-z./-]+"
        cleartextProtocolUrl = setRetrofitBaseUrl.hasString(regexRule, True)

        if cleartextProtocolUrl:
            print(f"CWE-319 detected!")
            print(f"Here are the found URLs with cleartext protocol:")
            print("\n".join(cleartextProtocolUrl))
```

## Quark Rule: setRetrofitBaseUrl.json

```json
{
    "crime": "Set Retrofit Base Url",
    "permission": [],
    "api":
    [
        {
            "descriptor": "()V",
            "class": "Lretrofit2/Retrofit$Builder;",
            "method": "<init>"
        },
        {
            "descriptor": "(Ljava/lang/String;)Lretrofit2/Retrofit$Builder;",
            "class": "Lretrofit2/Retrofit$Builder;",
            "method": "baseUrl"
        }
    ],
    "score": 1,
    "label": []
}
```

## Quark Script Result

```
$ python3 CWE-319.py
CWE-319 detected!
Here are the found URLs with cleartext protocol:
http://example.com./api/v1/
```
