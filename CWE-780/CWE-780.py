from quark.script import Rule, runQuarkAnalysis

SAMPLE_PATH = "MSTG-Android-Java.apk"
RULE_PATH = "useOfCryptographicAlgo.json"

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for useCryptographicAlgo in quarkResult.behaviorOccurList:

    methodCaller = useCryptographicAlgo.methodCaller

    if useCryptographicAlgor.hasString("RSA") and \
        not useCryptographicAlgo.hasString("OAEP"):
        print(f"CWE-780 is detected in method, {methodCaller.fullName}")