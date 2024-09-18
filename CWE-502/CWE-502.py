from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "pivaa.apk"
RULE_PATH = "deserializeData.json"

ruleInstance = Rule(RULE_PATH)

result = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

verificationApis = [
    ["Ljava/io/File;", "exists", "()Z"],
    ["Landroid/content/Context;", "getFilesDir", "()Ljava/io/File;"],
    ["Landroid/content/Context;", "getExternalFilesDir", "(Ljava/lang/String;)Ljava/io/File;"],
    ["Landroid/os/Environment;", "getExternalStorageDirectory", "()Ljava/io/File;"],
]

for dataDeserialization in result.behaviorOccurList:
    apis = dataDeserialization.getMethodsInArgs()
    caller = dataDeserialization.methodCaller
    if not any(api in apis for api in verificationApis):
        print(f"CWE-502 is detected in method, {caller.fullName}")