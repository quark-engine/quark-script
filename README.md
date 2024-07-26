# Quark Script Agent

Quark Script Agent is designed to help users easily utilize the Quark Script API to analyze their desired targets.

Quark Script Agent allows users to seamlessly add custom analysis features to the Quark Script API.

Quark Script Agent integrates with LangChain, connecting large language models with the Quark Script API. This integration enables users to perform analyses using natural language commands. By leveraging the power of LangChain and large language models, Quark Script Agent simplifies the process of interacting with the Quark Script API, making it accessible even to those who may not be familiar with programming or scripting.

## Use case of Quark Script CWE-798

> Since LangChain currently does not support passing Python instances between tools, we are temporarily using global variables to pass parameters between tools in quarkScriptAgent.py.

Quark Script CWE-798 analysis process:

1. Use the Quark Script API `Rule()` to define behavior.
2. Use the Quark Script API `runQuarkAnalysis()` to locate the  behavior.
4. Use the Quark Script API `getParameterValues()` to retrieve parameter values.
5. Use the Quark Script API `isHardCoded()` to check if a parameter is hard-coded.

The `Rule()`, `runQuarkAnalysis()`, `getParameterValues()`, and `isHardCoded()` functions are treated as **tools** within LangChain, enabling them to be invoked through the `gpt-4o` model to analyze and identify [CWE-798](https://cwe.mitre.org/data/definitions/798.html) vulnerabilities in the [ovaa.apk](https://github.com/oversecured/ovaa) sample.


#### Architecture

![](https://hackmd.io/_uploads/H1B-R6eYC.png)

#### Prompt
> Initialize rule instance with the rule path set to "rule.json"

> Run Quark Analysis using the rule instance on the apk sample "ovaa.apk", and Check if the parameters are hard-coded. If yes, display the hard-coded values.

#### Result

![](https://hackmd.io/_uploads/SJ0yopeY0.png)

#### rule.json

```json=
{
    "crime": "Detect APK using SecretKeySpec.",
    "permission": [],
    "api": [
        {
            "descriptor": "()[B",
            "class": "Ljava/lang/String;",
            "method": "getBytes"
        },
        {
            "descriptor": "([BLjava/lang/String;)V",
            "class": "Ljavax/crypto/spec/SecretKeySpec;",
            "method": "<init>"
        }
    ],
    "score": 1,
    "label": []
}
```

## Quickstart Quark Script

In this tutorial, we will learn how to install and run Quark Script with a very easy example.
We show how to detect CWE-798 in ovaa.apk. 

### STEP 1: Environments Requirements
* Quark Script requires Python 3.8+

### STEP 2: Install Quark Engine
You can install Quark Engine by running:
  ```
  pip3 install quark-engine
  ```

### STEP 3: Prepare Quark Script, Detection Rule and the Sample File
1. Get the CWE-798 Quark Script and the detection rule [here](https://quark-engine.readthedocs.io/en/latest/quark_script.html#detect-cwe-798-in-android-application-ovaa-apk).
2. Get the sampe file (ovaa.apk) [here](https://github.com/dark-warlord14/ovaa/releases/tag/1.0).
3. Put the script, detection rule, and sample file in the same directory.
4. Edit accordingly to the file names:
```python
SAMPLE_PATH = "ovaa.apk"
RULE_PATH = "findSecretKeySpec.json"
```

### STEP 4: Run the script
```
python3 CWE-798.py
```

You should now see the detection result in the terminal:
```
Found hard-coded AES key 49u5gh249gh24985ghf429gh4ch8f23f
```
