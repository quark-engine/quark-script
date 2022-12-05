# Detect CWE-926 in Android Application (dvba.apk)

This scenario seeks to find improper export of Android application components in the APK file. See [CWE-926](https://cwe.mitre.org/data/definitions/926.html) for more details.

Let’s use this [APK](https://github.com/rewanthtammana/Damn-Vulnerable-Bank) and the above APIs to show how Quark script find this vulnerability.

First, we use Quark API getActivities to get all activity data in the manifest. Then we use activityInstance.hasIntentFilter to check if the activities have intent-filter. Also, we use activityInstance.isExported to check if the activities set the attribute android:exported=true. If both are true, then the APK exports the component for use by other applications. That may cause CWE-926 vulnerabilities.
## Quark Script CWE-926.py
```
from quark.script import *

SAMPLE_PATH = "dvba.apk"

for activityInstance in getActivities(SAMPLE_PATH):

    if activityInstance.hasIntentFilter() and activityInstance.isExported():
        print(f"CWE-926 is detected in the activity, {activityInstance}")
```
## Quark Script Result
```
$ python3 CWE-926.py

CWE-926 is found in the activity, com.app.damnvulnerablebank.CurrencyRates
CWE-926 is found in the activity, com.app.damnvulnerablebank.SplashScreen
```
