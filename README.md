# Quickstart Quark Script

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
