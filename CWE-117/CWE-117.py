from quark.script import Rule, runQuarkAnalysis

SAMPLE_PATH = "allsafe.apk"
RULE_PATH = "writeContentToLog.json"
KEYWORDS_FOR_NEUTRALIZATION = ["escape", "replace", "format", "setFilter"]

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for logOutputBehavior in quarkResult.behaviorOccurList:

    secondAPIParam = logOutputBehavior.secondAPI.getArguments()

    isKeywordFound = False
    for keyword in KEYWORDS_FOR_NEUTRALIZATION:
        if keyword in secondAPIParam:
            isKeywordFound = True
            break

    if not isKeywordFound:
        caller = logOutputBehavior.methodCaller.fullName
        print(f"CWE-117 is detected in method, {caller}")