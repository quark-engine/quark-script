from quark.script import checkMethodCalls, getReceivers

SAMPLE_PATHS = ["AndroGoat.apk", "InsecureBankv2.apk"]

TARGET_METHOD = [
    '',
    'onReceive',
    '(Landroid/content/Context; Landroid/content/Intent;)V'
]

CHECK_METHODS = [
    ['Landroid/content/Intent;', 'getAction', '()Ljava/lang/String;']
]

for filepath in SAMPLE_PATHS:
    receivers = getReceivers(filepath)
    for receiver in receivers:
        if receiver.isExported():
            className = "L"+str(receiver).replace('.', '/')+';'
            TARGET_METHOD[0] = className
            if not checkMethodCalls(filepath, TARGET_METHOD, CHECK_METHODS):
                print(f"CWE-925 is detected in method, {className}")

