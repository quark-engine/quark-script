from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "Vuldroid.apk"
RULE_PATH = "ExternalStringCommand.json"


STRING_MATCHING_API = [
    ["Ljava/lang/String;", "contains", "(Ljava/lang/CharSequence)Z"],
    ["Ljava/lang/String;", "indexOf", "(I)I"],
    ["Ljava/lang/String;", "indexOf", "(Ljava/lang/String;)I"],
    ["Ljava/lang/String;", "matches", "(Ljava/lang/String;)Z"],
    ["Ljava/lang/String;", "replaceAll",
        "(Ljava/lang/String; Ljava/lang/String;)Ljava/lang/String;"],
]

delimiters = [' ', ';', '||', '|', ',', '>', '>>', '`']

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for ExternalStringCommand in quarkResult.behaviorOccurList:

    caller = ExternalStringCommand.methodCaller

    strMatchingAPIs = [
        api for api in STRING_MATCHING_API if
        quarkResult.findMethodInCaller(caller, api)
    ]

    if not strMatchingAPIs or \
            any(dlm not in strMatchingAPIs for dlm in delimiters):
        print(f"CWE-88 is detected in method, {caller.fullName}")
