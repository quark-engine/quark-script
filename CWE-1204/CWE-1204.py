from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "InsecureBankv2.apk"
RULE_PATH = "initializeCipherWithIV.json"

randomAPIs = [
    ["Ljava/security/SecureRandom", "next", "(I)I"],
    ["Ljava/security/SecureRandom", "nextBytes", "([B)V"],
]

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for initCipherWithIV in quarkResult.behaviorOccurList:
    methodcaller = initCipherWithIV.methodCaller

    if not any(
        initCipherWithIV.isArgFromMethod(api) for api in randomAPIs
    ):
        print(f"CWE-1204 is detected in method, {methodcaller.fullName}")
