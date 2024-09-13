from quark.script import checkMethodCalls, getReceivers

sample_path = "InsecureBankv2.apk"

TARGET_METHOD = [
    '',
    'onReceive',
    '(Landroid/content/Context; Landroid/content/Intent;)V'
]

CHECK_METHODS = [
    ['Landroid/content/Intent;', 'getAction', '()Ljava/lang/String;']
]

receivers = getReceivers(sample_path)
for receiver in receivers:
    if receiver.isExported():
        className = "L"+str(receiver).replace('.', '/')+';'
        TARGET_METHOD[0] = className
        if not checkMethodCalls(sample_path, TARGET_METHOD, CHECK_METHODS):
            print(f"CWE-925 is detected in method, {className}")