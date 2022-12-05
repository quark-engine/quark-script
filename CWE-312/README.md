# Detect CWE-312 in Android Application (ovaa.apk)

This scenario seeks to find cleartext storage of sensitive data in the APK file. See [CWE-312](https://cwe.mitre.org/data/definitions/312.html) for more details.

Let’s use this [APK](https://github.com/oversecured/ovaa) and the above APIs to show how Quark script find this vulnerability.

First, we designed a Frida script agent.js to hook the target method and get the arguments when the target method is called. Then we hook the method putString to catch its arguments. Finally, we use Ciphey to check if the arguments are encrypted.
## Quark Script CWE-312.py
```python
from quark.script.frida import runFridaHook
from quark.script.ciphey import checkClearText

APP_PACKAGE_NAME = "oversecured.ovaa"

TARGET_METHOD = "android.app." \
                "SharedPreferencesImpl$EditorImpl." \
                "putString"

METHOD_PARAM_TYPE = "java.lang.String," \
                    "java.lang.String"

fridaResult = runFridaHook(APP_PACKAGE_NAME,
                            TARGET_METHOD,
                            METHOD_PARAM_TYPE,
                        secondToWait = 10)

for putString in fridaResult.behaviorOccurList:

    firstParam, secondParam = putString.getParamValues()

    if firstParam in ["email", "password"] and \
        secondParam == checkClearText(secondParam):

        print(f'The CWE-312 vulnerability is found. The cleartext is "{secondParam}"')
```
## Frida Script: agent.js
```js
// -*- coding: utf-8 -*-
// This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
// See the file 'LICENSE' for copying permission.

/*global Java, send, rpc*/
function replaceMethodImplementation(targetMethod, classAndMethodName, methodParamTypes, returnType) {
    targetMethod.implementation = function () {
        let callEvent = {
            "type": "CallCaptured",
            "identifier": [classAndMethodName, methodParamTypes, returnType],
            "paramValues": []
        };

        for (const arg of arguments) {
            callEvent["paramValues"].push((arg || "(none)").toString());
        }

        send(JSON.stringify(callEvent));
        return targetMethod.apply(this, arguments);
    };
}

function watchMethodCall(classAndMethodName, methodParamTypes) {
    if (classAndMethodName == null || methodParamTypes == null) {
        return;
    }

    const indexOfLastSeparator = classAndMethodName.lastIndexOf(".");
    const classNamePattern = classAndMethodName.substring(0, indexOfLastSeparator);
    const methodNamePattern = classAndMethodName.substring(indexOfLastSeparator + 1);

    Java.perform(() => {
        const classOfTargetMethod = Java.use(classNamePattern);
        const possibleMethods = classOfTargetMethod[`${methodNamePattern}`];

        if (typeof possibleMethods === "undefined") {
            const failedToWatchEvent = {
                "type": "FailedToWatch",
                "identifier": [classAndMethodName, methodParamTypes]
            };

            send(JSON.stringify(failedToWatchEvent));
            return;
        }

        possibleMethods.overloads.filter((possibleMethod) => {
            const paramTypesOfPossibleMethod = possibleMethod.argumentTypes.map((argument) => argument.className);
            return paramTypesOfPossibleMethod.join(",") === methodParamTypes;
        }).forEach((matchedMethod) => {
            const retType = matchedMethod.returnType.name;
            replaceMethodImplementation(matchedMethod, classAndMethodName, methodParamTypes, retType);
        }
        );

    });
}

rpc.exports["watchMethodCall"] = (classAndMethodName, methodParamTypes) => watchMethodCall(classAndMethodName, methodParamTypes);
```
## Quark Script Result
```
$ python3 CWE-312.py
The CWE-312 vulnerability is found. The cleartext is "test@email.com"
The CWE-312 vulnerability is found. The cleartext is "password"
```
