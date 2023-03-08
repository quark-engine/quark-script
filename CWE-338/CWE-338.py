from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "pivaa.apk"
RULE_PATH = "useMethodOfPRNG.json"

CREDENTIAL_KEYWORDS = [
    "token", "password", "account", "encrypt",
    "authentication", "authorization", "id", "key"
]

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for usePRNGMethod in quarkResult.behaviorOccurList:
    for prngCaller in usePRNGMethod.methodCaller.getXrefFrom():
        if any(keyword in prngCaller.fullName
               for keyword in CREDENTIAL_KEYWORDS):
            print("CWE-338 is detected in %s" % prngCaller.fullName)