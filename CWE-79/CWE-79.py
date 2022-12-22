from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "Vuldroid.apk"
RULE_PATH = "loadUrlFromIntent.json"

XSS_FILTERS = [
    [
        "Lorg/owasp/esapi/Validator;", "getValidSafeHTML",
        "(Ljava/lang/String; Ljava/lang/String; I Z)Ljava/lang/String;",
    ],
    [
        "Lorg/owasp/esapi/Encoder;", "encodeForHTML",
        "(Ljava/lang/String;)Ljava/lang/String;",
    ],
    [
        "Lorg/owasp/esapi/Encoder;", "encodeForJavaScript",
        "(Ljava/lang/String;)Ljava/lang/String;",
    ],
    [
        "Lorg/owasp/html/PolicyFactory;", "sanitize",
        "(Ljava/lang/String;)Ljava/lang/String;",
    ],
]

targetMethod = [
    "Landroid/webkit/WebSettings;", "setJavaScriptEnabled",
    "(Z)V"
]

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for loadUrl in quarkResult.behaviorOccurList:
    caller = loadUrl.methodCaller
    setJS = quarkResult.findMethodInCaller(caller, targetMethod)
    enableJS = []

    if setJS:
        enableJS = setJS[0].getArguments()[1]

    if enableJS:
        XSSFiltersInCaller = [
            filterAPI for filterAPI in XSS_FILTERS if quarkResult.findMethodInCaller(caller, filterAPI)
        ]

        if not XSSFiltersInCaller:
            print(f"CWE-79 is detected in method, {caller.fullName}")
