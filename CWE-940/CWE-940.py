from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "ovaa.apk"
RULE_PATH = "LoadUrlFromIntent.json"

URL_GETTING_METHODS = [
    "findViewById",
    "getStringExtra",
    "getIntent",
]

ruleInstance = Rule(RULE_PATH)

quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for behaviorInstance in quarkResult.behaviorOccurList:
    methodsInArgs = behaviorInstance.getMethodsInArgs()

    verifiedMethodCandidates = []

    for method in methodsInArgs:
        if method.methodName not in URL_GETTING_METHODS:
            verifiedMethodCandidates.append(method)

    if verifiedMethodCandidates == []:
        caller = behaviorInstance.methodCaller.fullName
        print(f"CWE-940 is detected in method, {caller}")
