#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Mar  2 08:24:30 2023

@author: poyenliang
"""

from quark.script import runQuarkAnalysis, Rule

SAMPLE_PATH = "ovaa.apk"
RULE_PATH = "accessFileInExternalDir.json"


STRING_MATCHING_API = [
    ["Ljava/lang/String;", "contains", "(Ljava/lang/CharSequence)Z"],
    ["Ljava/lang/String;", "indexOf", "(I)I"],
    ["Ljava/lang/String;", "indexOf", "(Ljava/lang/String;)I"],
    ["Ljava/lang/String;", "matches", "(Ljava/lang/String;)Z"],
    ["Ljava/lang/String;", "replaceAll",
        "(Ljava/lang/String; Ljava/lang/String;)Ljava/lang/String;"],
]

ruleInstance = Rule(RULE_PATH)
quarkResult = runQuarkAnalysis(SAMPLE_PATH, ruleInstance)

for accessExternalDir in quarkResult.behaviorOccurList:

    filePath = accessExternalDir.secondAPI.getArguments()[2]

    if quarkResult.isHardcoded(filePath):
        continue

    caller = accessExternalDir.methodCaller
    strMatchingAPIs = [
        api for api in STRING_MATCHING_API if quarkResult.findMethodInCaller(
            caller, api)
    ]

    if not strMatchingAPIs:
        print(f"CWE-23 is detected in method, {caller.fullName}")
    elif strMatchingAPIs.find("..") == -1:
        print(f"CWE-23 is detected in method, {caller.fullName}")