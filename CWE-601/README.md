Detect CWE-601 in Android Application (ovaa)
------------------------------------------------------

This scenario aims to demonstrate the detection of the **URL Redirection to Untrusted Site** vulnerability using [ovaa.apk](https://github.com/oversecured/ovaa). See [CWE-601](https://cwe.mitre.org/data/definitions/601.html) for more details.

To detect the vulnerability, we need to find all the caller methods of ``startActivity`` API that might receive external input without input validation. The ``findMethodInAPK`` function finds all the methods in the APK file that call the ``startActivity`` API. Next, we examine the arguments of each method to discover the methods receiving external input. If a method receives external input but lacks of proper input validation, the CWE-601 vulnerability is identified.

Quark Script CWE-601.py
==========================

The Quark Script below uses ovaa.apk to demonstrate.

```python


from quark.script import findMethodInAPK

SAMPLE_PATH = 'ovaa.apk'

# This is the input for findMethodInAPK, formatted as class name, method name, descriptor
TARGET_METHOD = ["", "startActivity", "(Landroid/content/Intent;)V"]  

"""
Due to varying descriptors and classes in smali code from different APIs, 
our search relies solely on the consistent method names.
"""

EXTERNAL_INPUT_METHODS = [
   "getIntent", 
   "getQueryParameter"
]

INPUT_FILTER_METHODS = [
   "parse", 
   "isValidUrl", 
   "Pattern", 
   "Matcher", 
   "encode", 
   "decode", 
   "escapeHtml", 
   "HttpURLConnection"
]

redirectMethods = findMethodInAPK(SAMPLE_PATH, TARGET_METHOD)

for redirectMethod in redirectMethods:
   arguments = redirectMethod.getArguments()
   for argument in arguments:
       if any(externalInput in argument for
           externalInput in EXTERNAL_INPUT_METHODS):
           if not any(filterMethod in argument for
               filterMethod in INPUT_FILTER_METHODS):
               print(f"CWE-601 is detected in {redirectMethod.fullName}")





```

Quark Script Result
======================
- **ovaa.apk**

```

$ python CWE-601.py
CWE-601 is detected in Loversecured/ovaa/activities/DeeplinkActivity; processDeeplink (Landroid/net/Uri;)V
CWE-601 is detected in Loversecured/ovaa/activities/LoginActivity; onLoginFinished ()V

```