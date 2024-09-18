# Detect CWE-601 in Android Application

This scenario seeks to find **URL Redirection to Untrusted Site** in the
APK file.

## CWE-601: URL Redirection to Untrusted Site (\'Open Redirect\')

We analyze the definition of CWE-601 and identify its characteristics.

See [CWE-601](https://cwe.mitre.org/data/definitions/601.html) for more
details.

![image](https://imgur.com/sgRhcel.png)

## Code of CWE-601 in ovaa.apk

We use the [ovaa.apk](https://github.com/oversecured/ovaa) sample to
explain the vulnerability code of CWE-601.

![image](https://imgur.com/I61pL2m.png)

## Quark Script: CWE-601.py

Let's use the above APIs to show how the Quark script finds this
vulnerability.

To detect the vulnerability, we use the API
`findMethodInAPK(samplePath, targetMethod)` to find all the caller
methods of `startActivity`. Next, we examine the arguments of each
method to discover the methods receiving external input. If a method
receives external input but lacks proper input validation, the CWE-601
vulnerability is identified.

``` python
from quark.script import findMethodInAPK

SAMPLE_PATH = 'ovaa.apk'

# This is the input for findMethodInAPK, formatted as class name, method name, descriptor
TARGET_METHOD = ["", "startActivity", "(Landroid/content/Intent;)V"]

"""
Due to varying descriptors and classes in smali code from different APIs,
our search relies solely on the consistent method names.
"""

EXTERNAL_INPUT_METHODS = ["getIntent", "getQueryParameter"]

INPUT_FILTER_METHODS = [
    "parse",
    "isValidUrl",
    "Pattern",
    "Matcher",
    "encode",
    "decode",
    "escapeHtml",
    "HttpURLConnection",
]

redirectMethods = findMethodInAPK(SAMPLE_PATH, TARGET_METHOD)

for redirectMethod in redirectMethods:
    arguments = redirectMethod.getArguments()
    for argument in arguments:
        if any(
            externalInput in argument
            for externalInput in EXTERNAL_INPUT_METHODS
        ):
            if not any(
                filterMethod in argument
                for filterMethod in INPUT_FILTER_METHODS
            ):
                print(f"CWE-601 is detected in {redirectMethod.fullName}")
```

## Quark Script Result

``` TEXT
$ python CWE-601.py
CWE-601 is detected in Loversecured/ovaa/activities/DeeplinkActivity; processDeeplink (Landroid/net/Uri;)V
CWE-601 is detected in Loversecured/ovaa/activities/LoginActivity; onLoginFinished ()V
```
