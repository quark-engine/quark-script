# Detect CWE-319 in Android Application


This scenario seeks to find **Cleartext Transmission of Sensitive
Information** in the APK file.

## CWE-319 Cleartext Transmission of Sensitive Information

We analyze the definition of CWE-319 and identify its characteristics.

See [CWE-319](https://cwe.mitre.org/data/definitions/319.html) for more
details.

![image](https://imgur.com/tk8rtYf.jpg)

## Code of CWE-319 in ovaa.apk

We use the [ovaa.apk](https://github.com/oversecured/ovaa) sample to
explain the vulnerability code of CWE-319.

![image](https://imgur.com/Ew4UOAR.jpg)

## Quark Script: CWE-319.py

Let\'s use the above APIs to show how the Quark script finds this
vulnerability. This sample uses the package Retrofit to request Web
APIs, but the APIs use cleartext protocols.

We first design a detection rule `setRetrofitBaseUrl.json` to spot on
behavior that sets the base URL of the Retrofit instance. Then, we loop
through a custom list of cleartext protocol schemes and use API
`behaviorInstance.hasString(pattern, isRegex)` to filter arguments that
are URL strings with cleartext protocol.

``` python
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

``` json
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

``` TEXT
$ python3 CWE-319.py
CWE-319 detected!
Here are the found URLs with cleartext protocol:
http://example.com./api/v1/
```
