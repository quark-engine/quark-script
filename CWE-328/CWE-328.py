from quark.script import findMethodInAPK

SAMPLE_PATHS = [
        "./allsafe.apk",   "./ovaa.apk",
        "./AndroGoat.apk", "./MSTG-Android-Java.apk"
]

TARGET_METHODS = [
    [
        "Ljava/security/MessageDigest;", "getInstance",
        "(Ljava/lang/String;)Ljava/security/MessageDigest;"
    ],
    [
        "Ljavax/crypto/SecretKeyFactory;", "getInstance",
        "(Ljava/lang/String;)Ljavax/crypto/SecretKeyFactory;"
    ]
]

HASH_KEYWORDS = [
    "MD2",  "MD4",  "MD5",      "PANAMA",
    "SHA0", "SHA1", "HAVAL128", "RIPEMD128"
]

for samplePath in SAMPLE_PATHS:

    methodsFound = []
    for target in TARGET_METHODS:
        methodsFound += findMethodInAPK(samplePath, target)

    for setHashAlgo in methodsFound:
        algoName = setHashAlgo.getArguments()[0].replace("-", "")

        if any(keyword in algoName for keyword in HASH_KEYWORDS):
            print(f"CWE-328 is detected in {samplePath},\n\t"
                  f"and it occurs in method, {setHashAlgo.fullName}")
