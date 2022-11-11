from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "ovaa.apk"
RULE_PATH = "loadExternalCode.json"

targetMethod = [
        "Landroid/content/pm/PackageManager;",
        "checkSignatures",
        "(Ljava/lang/String;Ljava/lang/String;)I"
        ]

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for ldExternalCode in quarkResult.behaviorOccurList:

    callerMethod = [
            ldExternalCode.methodCaller.className,
            ldExternalCode.methodCaller.methodName,
            ldExternalCode.methodCaller.descriptor
            ]

    if not quarkResult.findMethodInCaller(callerMethod, targetMethod):
        print(f"\nMethod: {targetMethod[1]} not found!")
        print(f"CWE-94 is detected in {SAMPLE_PATH}")