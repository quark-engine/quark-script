from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "diva.apk"
RULE_PATH = "openUrlThatUserInput.json"

rule = Rule(RULE_PATH)
result = runQuarkAnalysis(SAMPLE_PATH, rule)

VALIDATE_METHODS = ["contains", "indexOf", "matches", "replaceAll"]

for openUrl in result.behaviorOccurList:
    calledMethods = openUrl.getMethodsInArgs()

    if not any(method.methodName in VALIDATE_METHODS
               for method in calledMethods):
        print("CWE-20 is detected in method,"
              f"{openUrl.methodCaller.fullName}")
