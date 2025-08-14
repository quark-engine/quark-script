from quark.script import findMethodImpls, isMethodReturnAlwaysTrue

SAMPLE_PATH = "pivaa.apk"

ABSTRACT_METHOD = [
    "Ljavax/net/ssl/HostnameVerifier;",
    "verify",
    "(Ljava/lang/String; Ljavax/net/ssl/SSLSession;)Z"
]

for hostVerification in findMethodImpls(SAMPLE_PATH, ABSTRACT_METHOD):
    methodImpls = [
        hostVerification.className,
        hostVerification.methodName,
        hostVerification.descriptor
    ]
    if isMethodReturnAlwaysTrue(SAMPLE_PATH, methodImpls):
        print(f"CWE-297 is detected in method, {hostVerification.fullName}")
