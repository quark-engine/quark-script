# Quark Script Agent

Introducing Quark's new member, the Quark Script Agent, the first AI assistant in the Quark team. This agent enables users to perform analyses using natural language, without the need for programming or scripting expertise, making the process simple and user-friendly.

The Quark Script Agent integrates with LangChain, which utilizes OpenAI's large language models to act as a bridge between natural language and the Quark Script API. LangChain defines the Quark Script API as a tool that large language models can understand and use. This means that users can easily call new analysis APIs using natural language commands by simply adding new tools as needed.


Here's an example of using the Quark Script Agent with the `quarkScriptAgent.py`. This agent can currently detect [CWE-798](https://cwe.mitre.org/data/definitions/798.html) vulnerabilities in the [ovaa.apk](https://github.com/oversecured/ovaa). See the details below.

> Since LangChain currently does not support passing Python instances between tools, we are temporarily using global variables to pass parameters between tools in `quarkScriptAgent.py`.

## Use case of Quark Script CWE-798

### Installation

To install the Quark Script Agent, you need to install the following dependencies:

1. clone the repository:
```
git clone https://github.com/quark-engine/quark-script.git
```

2. Install the required packages:
```
pip install -r requirements.txt
```

3. Run the script:
```
python quarkScriptAgent.py
```

### Analysis Process

Quark Script CWE-798 analysis process:

1. Use the Quark Script API `Rule()` to define behavior in the `rule.json` file.
2. Use the Quark Script API `runQuarkAnalysis()` to locate the behavior.
4. Use the Quark Script API `getParameterValues()` to retrieve parameter values.
5. Use the Quark Script API `isHardCoded()` to check if a parameter is hard-coded.

the `rule.json` file contains the following information:

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

The `Rule()`, `runQuarkAnalysis()`, `getParameterValues()`, and `isHardCoded()` functions are treated as **tools** within LangChain, enabling them to be invoked through the `gpt-4o` model to analyze and identify [CWE-798](https://cwe.mitre.org/data/definitions/798.html) vulnerabilities in the [ovaa.apk](https://github.com/oversecured/ovaa) sample.


### Architecture

<img width="829" alt="截圖 2024-07-26 下午3 40 32" src="https://github.com/user-attachments/assets/f17bfba0-43d7-4236-9775-bb0d3b961907">

### Prompts

Here are two prompts, each for executing different analysis process.

**analysis process**

1. Use the Quark Script API `Rule()` to define behavior in the `rule.json` file.

**prompt**

`Initialize rule instance with the rule path set to "rule.json"`

**analysis process**

2. Use the Quark Script API `runQuarkAnalysis()` to locate the behavior.
3. Use the Quark Script API `getParameterValues()` to retrieve parameter values.
4. Use the Quark Script API `isHardCoded()` to check if a parameter is hard-coded.

**prompt**
`Run Quark Analysis using the rule instance on the apk sample "ovaa.apk", and Check if the parameters are hard-coded. If yes, display the hard-coded values.`

### Result

<img width="1440" alt="截圖 2024-07-26 下午3 39 12" src="https://github.com/user-attachments/assets/9c8ba9d3-c8b5-4583-8cb8-750f8c3bf2a7">



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
