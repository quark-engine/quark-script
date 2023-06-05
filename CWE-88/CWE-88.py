from quark.script import runQuarkAnalysis, Rule, findMethodInAPK

SAMPLE_PATH = "Vuldroid.apk"
RULE_PATH = "ExternalStringCommand.json"


STRING_MATCHING_API = set([
    ("Ljava/lang/String;", "contains", "(Ljava/lang/CharSequence)Z"),
    ("Ljava/lang/String;", "indexOf", "(I)I"),
    ("Ljava/lang/String;", "indexOf", "(Ljava/lang/String;)I"),
    ("Ljava/lang/String;", "matches", "(Ljava/lang/String;)Z"),
    ("Ljava/lang/String;", "replaceAll", "(Ljava/lang/String; Ljava/lang/String;)Ljava/lang/String;")
])

delimeter = "-"

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for ExternalStringCommand in quarkResult.behaviorOccurList:

    methodCalled = set()
    caller = ExternalStringCommand.methodCaller

    for method in ExternalStringCommand.getMethodsInArgs():
        methodCalled.add(method.fullName)

    if methodCalled.intersection(STRING_MATCHING_API):
        if not ExternalStringCommand.hasString(delimeter):
            print(f"CWE-88 is detected in method, {caller.fullName}")
    else:
        print(f"CWE-88 is detected in method, {caller.fullName}")
