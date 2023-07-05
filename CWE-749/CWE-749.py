from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "MSTG-Android-Java.apk"
RULE_PATH = "configureJsExecution.json"

targetMethod = [
    "Landroid/webkit/WebView;",
    "addJavascriptInterface",
    "(Ljava/lang/Object; Ljava/lang/String;)V"
]

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for configureJsExecution in quarkResult.behaviorOccurList:

    caller = configureJsExecution.methodCaller
    secondAPI = configureJsExecution.secondAPI

    # Check if arguments list has at least two elements
    arguments = secondAPI.getArguments()
    if len(arguments) >= 2:
        enableJS = arguments[1]
        exposeAPI = quarkResult.findMethodInCaller(caller, targetMethod)

        if enableJS and exposeAPI:
            print(f"CWE-749 is detected in method, {caller.fullName}")
