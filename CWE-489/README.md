## Detect CWE-489 in Android Application (allsafe.apk)

This scenario seeks to find **active debug code** in the APK file. See [CWE-489](https://cwe.mitre.org/data/definitions/489.html) for more details.

Let’s use [allsafe.apk](https://github.com/t0thkr1s/allsafe), [AndroGoat.apk](https://github.com/satishpatnayak/AndroGoat), [pivaa.apk](https://github.com/HTBridge/pivaa), and the above APIs to show how the Quark script finds this vulnerability.

First, we use Quark API `getApplication` to get the application element in the manifest file. Then we use `applicationInstance.isDebuggable` to check if the application element sets the attribute `android:debuggable` to true. If **Yes**, that causes CWE-489 vulnerabilities.


### Quark Script CWE-489.py

The Quark Script below uses allsafe.apk to demonstrate. You can change the `SAMPLE_PATH` to the sample you want to detect. For example, `SAMPLE_PATH = AndroGoat.apk` or `SAMPLE_PATH = pivaa.apk`.

```python
from quark.script import getApplication

SAMPLE_PATH = "allsafe.apk"

if getApplication(SAMPLE_PATH).isDebuggable():
    print(f"CWE-489 is detected in {SAMPLE_PATH}.")
```

### Quark Script Result

-   **allsafe.apk**

```
$ python3 CWE-489.py
CWE-489 is detected in allsafe.apk
```

-   **AndroGoat.apk**

``` 
$ python3 CWE-489.py
CWE-489 is detected in AndroGoat.apk
```
-   **pivaa.apk**
    
```
$ python3 CWE-489.py
CWE-489 is detected in pivaa.apk
```
