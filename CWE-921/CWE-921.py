from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "ovaa.apk"
RULE_PATH = "checkFileExistence.json"

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for existingFile in quarkResult.behaviorOccurList:
    filePath = existingFile.getParamValues()[0]
    if "sdcard" in filePath:
        print(f"This file is stored inside the SDcard\n")
        print(f"CWE-921 is detected in {SAMPLE_PATH}.")