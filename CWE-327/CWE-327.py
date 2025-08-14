from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "InjuredAndroid.apk"
RULE_PATH = "useOfCryptographicAlgo.json"

WEAK_ALGORITHMS = ["DES", "ARC4", "BLOWFISH"]

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for useCryptoAlgo in quarkResult.behaviorOccurList:

    caller = useCryptoAlgo.methodCaller

    for algo in WEAK_ALGORITHMS:
        if useCryptoAlgo.hasString(algo):
            print(f"CWE-327 is detected in method, {caller.fullName}")
