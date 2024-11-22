from quark.script import findMethodInAPK

SAMPLE_PATH = "insecureShop.apk"
TARGET_METHOD = [
    "Landroid/webkit/SslErrorHandler;",  # class name
    "proceed",                           # method name
    "()V"                                # descriptor
]
OVERRIDDEN_METHOD = [
    "Landroid/webkit/WebViewClient;",    # class name
    "onReceivedSslError",                # method name
    "(Landroid/webkit/WebView;" + " Landroid/webkit/SslErrorHandler;" + \
    " Landroid/net/http/SslError;)V"     # descriptor
]

for sslProceedCaller in findMethodInAPK(SAMPLE_PATH, TARGET_METHOD):
    if (
        sslProceedCaller.name == OVERRIDDEN_METHOD[1]
        and sslProceedCaller.descriptor == OVERRIDDEN_METHOD[2]
        and OVERRIDDEN_METHOD[0] in sslProceedCaller.findSuperclassHierarchy()
    ):
        print(f"CWE-295 is detected in method, {sslProceedCaller.fullName}")
