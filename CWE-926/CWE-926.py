from quark.script import *

SAMPLE_PATH = "dvba.apk"

for activityInstance in getActivities(SAMPLE_PATH):

    if activityInstance.hasIntentFilter() and activityInstance.isExported():
        print(f"CWE-926 is detected in the activity, {activityInstance}")