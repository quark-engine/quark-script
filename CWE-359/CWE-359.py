from quark.script import Rule, runQuarkAnalysis, getProviders

SAMPLE_PATH = "ovaa.apk"
RULE_PATH = "accessFileWithUnsafeUriPath.json"

STRING_MATCHING_API = [
    ["Ljava/lang/String;", "contains", "(Ljava/lang/CharSequence)Z"],
    ["Ljava/lang/String;", "indexOf", "(I)I"],
    ["Ljava/lang/String;", "indexOf", "(Ljava/lang/String;)I"],
    ["Ljava/lang/String;", "matches", "(Ljava/lang/String;)Z"],
    [
        "Ljava/lang/String;",
        "replaceAll",
        "(Ljava/lang/String; Ljava/lang/String;)Ljava/lang/String;",
    ],
]

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

exportedProviders = [
    str(provider)
    for provider in getProviders(SAMPLE_PATH)
    if provider.isExported()
]

for behavior in quarkResult.behaviorOccurList:
    caller = behavior.methodCaller
    classNameInJavaFormat = caller.className.replace("/", ".")[1:-1]
    filePath = behavior.secondAPI.getArguments()[2]

    if quarkResult.isHardcoded(filePath):
        continue

    if classNameInJavaFormat not in exportedProviders:
        continue

    if not any(
        quarkResult.findMethodInCaller(caller, api)
        for api in STRING_MATCHING_API
    ):
        print(f"CWE-359 is detected in method, {caller.fullName}")
