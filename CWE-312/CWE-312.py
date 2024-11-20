from quark.script.frida import runFridaHook
from quark.script.ares import checkClearText

APP_PACKAGE_NAME = "oversecured.ovaa"

TARGET_METHOD = "android.app." "SharedPreferencesImpl$EditorImpl." "putString"

METHOD_PARAM_TYPE = "java.lang.String," "java.lang.String"

fridaResult = runFridaHook(
    APP_PACKAGE_NAME, TARGET_METHOD, METHOD_PARAM_TYPE, secondToWait=10
)

for putString in fridaResult.behaviorOccurList:

    firstParam = putString.firstAPI.getArguments()
    secondParam = putString.secondAPI.getArguments()

    if firstParam in ["email", "password"] and secondParam == checkClearText(
            secondParam
    ):

        print(
            "The CWE-312 vulnerability is found. "
            f'The cleartext is "{secondParam}"'
        )
