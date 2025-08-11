from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "./ovaa.apk"
RULE_PATH = "setRetrofitBaseUrl.json"

PROTOCOL_KEYWORDS = [
    "http",
    "smtp",
    "ftp"
]


ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for setRetrofitBaseUrl in quarkResult.behaviorOccurList:
    for protocol in PROTOCOL_KEYWORDS:

        regexRule = f"{protocol}://[0-9A-Za-z./-]+"
        cleartextProtocolUrl = setRetrofitBaseUrl.hasString(regexRule, True)

        if cleartextProtocolUrl:
            print(f"CWE-319 detected!")
            print(f"Here are the found URLs with cleartext protocol:")
            print("\n".join(cleartextProtocolUrl))
