import re
from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "ovaa.apk"
RULE_PATH = "findSecretKeySpec.json"

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for secretKeySpec in quarkResult.behaviorOccurList:

    firstParam = secretKeySpec.secondAPI.getArguments()[1]
    secondParam = secretKeySpec.secondAPI.getArguments()[2]

    if secondParam == "AES":
        AESKey = re.findall(r"\((.*?)\)", firstParam)[1]

        if quarkResult.isHardcoded(AESKey):
            print(f"Found hard-coded {secondParam} key {AESKey}")