from quark.script import runQuarkAnalysis, Rule


SAMPLE_PATH = "ovaa.apk"
RULE_PATH = "accessFileInExternalDir.json"

OPEN_FILE_API = [
    "Landroid/os/ParcelFileDescriptor;",                     # Class name
    "open",                                                  # Method name   
    "(Ljava/io/File; I)Landroid/os/ParcelFileDescriptor;"    # Descriptor
]

rule_instance = Rule(RULE_PATH)
quark_result = runQuarkAnalysis(SAMPLE_PATH, rule_instance)

for access_external_dir in quark_result.behavior_occur_list:
    file_path = access_external_dir.second_api.get_arguments()[2]

    if quark_result.is_hardcoded(file_path):
        continue

    caller = access_external_dir.method_caller
    result = quark_result.find_method_in_caller(caller, OPEN_FILE_API)

    if result:
        print("CWE-73 is detected in method:", caller.full_name)






    

    