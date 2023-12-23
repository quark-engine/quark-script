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




