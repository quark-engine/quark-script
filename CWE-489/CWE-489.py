from quark.script import getApplication

SAMPLE_PATH = "allsafe.apk"

if getApplication(SAMPLE_PATH).isDebuggable():
    print(f"CWE-489 is detected in {SAMPLE_PATH}.")
