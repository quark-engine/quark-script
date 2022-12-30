from quark.script import findMethodInAPK

SAMPLE_PATH = "insecureShop.apk"
TARGET_METHOD = [
    "Landroid/webkit/SslErrorHandler;",  # class name
    "proceed",                          # method name
    "()V"                               # descriptor
]
OVERRIDE_METHOD = [
    "Landroid/webkit/WebViewClient;",  # class name
    "onReceivedSslError",              # method name
    # descriptor
    "(Landroid/webkit/WebView;Landroid/webkit/SslErrorHandler;Landroid/net/http/SslError;)V"
]

for sslProceedCaller in findMethodInAPK(SAMPLE_PATH, TARGET_METHOD):
    if (sslProceedCaller.name == OVERRIDE_METHOD[1] and
       sslProceedCaller.descriptor == OVERRIDE_METHOD[2] and
       OVERRIDE_METHOD[0] in sslProceedCaller.findSuperclassHierarchy()):
        print(f"CWE-295 is detected in method, {sslProceedCaller.fullName}")
