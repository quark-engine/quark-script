# Detect CWE-312 in Android Application

This scenario seeks to find **cleartext storage of sensitive data** in the APK file.

## CWE-312: Cleartext Storage of Sensitive Information

We analyze the definition of CWE-312 and identify its characteristics.

See [CWE-312](https://cwe.mitre.org/data/definitions/312.html) for more details.

![image](https://imgur.com/mD2uXUy.jpg)

## Code of CWE-312 in ovaa.apk

We use the [ovaa.apk](https://github.com/oversecured/ovaa) sample to explain the vulnerability code of CWE-312.

![image](https://imgur.com/MfnYIYy.jpg)

## CWE-312 Detection Process Using Quark Script API

Let’s use the above APIs to show how the Quark script finds this vulnerability.

We have designed a [Frida](https://frida.re/) script ``agent.js`` to hook a specified method and get the arguments when the method is called. It can be found in [quark-engine/quark/script/frida](https://github.com/quark-engine/quark-engine/tree/master/quark/script/frida).
 
To begin with, we hook the method ``putString`` to catch its arguments. Then, we check if sensitive information like email or password is passed. Finally, we use ``checkClearText`` imported from [Ares](https://github.com/bee-san/Ares) to check if the arguments are cleartext. If both **YES**, CWE-312 vulnerability might be caused.

![image](https://imgur.com/eNjm3ES.jpg)

## Quark Script: CWE-312.py

![image](https://imgur.com/rxMPZX8.jpg)

```python
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
```

## Frida Script: agent.js

```javascript
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

```TEXT
$ python3 CWE-312.py
The CWE-312 vulnerability is found. The cleartext is "test@email.com"
The CWE-312 vulnerability is found. The cleartext is "password"
```
