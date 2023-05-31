from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "ovaa.apk"
RULE_PATH = "accessFileInExternalDir.json"

OPEN_FILE_API = [
    "Landroid/os/ParcelFileDescriptor;",                   # Class name
    "open",                                                # Method name
    "(Ljava/io/File; I)Landroid/os/ParcelFileDescriptor;"  # Descriptor
]

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for accessExternalDir in quarkResult.behaviorOccurList:
    filePath = accessExternalDir.secondAPI.getArguments()[2]

    if quarkResult.isHardcoded(filePath):
        continue

    caller = accessExternalDir.methodCaller
    result = quarkResult.findMethodInCaller(caller, OPEN_FILE_API)

    if result:
        print("CWE-73 is detected in method, ", caller.fullName)
