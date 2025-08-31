from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "ovaa.apk"
RULE_PATH = "putStrAndCommit.json"

encryptAPI = ["Ljavax/crypto/Cipher;", "doFinal", ""]

passwordPatterns = ["password", "pswd", "passwd"]


ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for putStrAndCommit in quarkResult.behaviorOccurList:
    paramValues = [
        paramValue.lower() for paramValue in putStrAndCommit.getParamValues()
    ]
    if not any(
        passwordPattern in paramValues for passwordPattern in passwordPatterns
    ):
        continue

    if not putStrAndCommit.isArgFromMethod(encryptAPI):
        print(
            f"CWE-256 is detected in method",
            putStrAndCommit.methodCaller.fullName
        )
