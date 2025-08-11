from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "AndroGoat.apk"
RULE_PATH = "executeSQLCommand.json"

targetMethod = [
    "Landroid/widget/EditText;", # class name
    "getText",                   # method name
    "()Landroid/text/Editable;", # descriptor
]

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for sqlCommandExecution in quarkResult.behaviorOccurList:
    if sqlCommandExecution.isArgFromMethod(
        targetMethod
    ):
        print(f"CWE-89 is detected in {SAMPLE_PATH}")
