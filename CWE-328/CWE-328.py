from quark.script import findMethodInAPK

SAMPLE_PATH = "./allsafe.apk"

TARGET_METHODS = [
    [
        "Ljava/security/MessageDigest;",
        "getInstance",
        "(Ljava/lang/String;)Ljava/security/MessageDigest;",
    ],
    [
        "Ljavax/crypto/SecretKeyFactory;",
        "getInstance",
        "(Ljava/lang/String;)Ljavax/crypto/SecretKeyFactory;",
    ],
]

HASH_KEYWORDS = [
    "MD2",
    "MD4",
    "MD5",
    "PANAMA",
    "SHA0",
    "SHA1",
    "HAVAL128",
    "RIPEMD128",
]

methodsFound = []
for target in TARGET_METHODS:
    methodsFound += findMethodInAPK(SAMPLE_PATH, target)

for setHashAlgo in methodsFound:
    algoName = setHashAlgo.getArguments()[0].replace("-", "")

    if any(keyword in algoName for keyword in HASH_KEYWORDS):
        print(
            f"CWE-328 is detected in {SAMPLE_PATH},\n\t"
            f"and it occurs in method, {setHashAlgo.fullName}"
        )