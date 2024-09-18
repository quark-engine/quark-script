# Detect CWE-926 in Android Application


This scenario seeks to find **Improper Export of Android Application
Components** in the APK file.

## CWE-926 Improper Export of Android Application Components

We analyze the definition of CWE-926 and identify its characteristics.

See [CWE-926](https://cwe.mitre.org/data/definitions/926.html) for more
details.

![image](https://imgur.com/Km8wtGs.jpg)

## Code of CWE-926 in dvba.apk

We use the
[dvba.apk](https://github.com/rewanthtammana/Damn-Vulnerable-Bank)
sample to explain the vulnerability code of CWE-926.

![image](https://imgur.com/KoOt5ii.jpg)

## Quark Script: CWE-926.py

Let\'s use the above APIs to show how the Quark script finds this
vulnerability.

First, we use Quark API `getActivities(samplePath)` to get all activity
data in the manifest. Then, we use `activityInstance.hasIntentFilter()`
to check if the activities have `intent-filter`. Also, we use
`activityInstance.isExported()` to check if the activities set the
attribute `android:exported=true`. If both are **true**, then the APK
exports the component for use by other applications. That may cause
CWE-926 vulnerabilities.

``` python
from quark.script import *

SAMPLE_PATH = "dvba.apk"

for activityInstance in getActivities(SAMPLE_PATH):

    if activityInstance.hasIntentFilter() and activityInstance.isExported():
        print(f"CWE-926 is detected in the activity, {activityInstance}")
```

## Quark Script Result

``` TEXT
$ python3 CWE-926.py
CWE-926 is detected in the activity, com.app.damnvulnerablebank.CurrencyRates
CWE-926 is detected in the activity, com.app.damnvulnerablebank.SplashScreen
```
