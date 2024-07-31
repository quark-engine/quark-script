import os

from termcolor import colored

from langchain_openai import ChatOpenAI
from langchain.agents import tool, AgentExecutor
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain.agents.output_parsers.openai_tools import OpenAIToolsAgentOutputParser
from langchain.agents.format_scratchpad.openai_tools import (
    format_to_openai_tool_messages,
)

from quark.script import Rule, _getQuark, QuarkResult

if "OPENAI_API_KEY" not in os.environ:
    api_key = input("OpenAI API Key: ")
    os.environ["OPENAI_API_KEY"] = api_key


conversation_history = []


@tool
def loadRule(rulePath: str):
    """
    Given a rule path,
    this instance loads a rule from the rule path.

    Used Quark Script API: Rule(rule.json)
    - description: Making detection rule a rule instance
    - params: Path of a single Quark rule
    - return: Quark rule instance
    - example:

        .. code:: python

            from quark.script import Rule

            ruleInstance = Rule("rule.json")

    """

    global ruleInstance
    ruleInstance = Rule(rulePath)

    return "Rule defined successfully"


@tool
def runQuarkAnalysis(samplePath: str):
    """
    Given detection rule and target sample,
    this instance runs the Quark Analysis.

    Used Quark Script API: runQuarkAnalysis(SAMPLE_PATH, ruleInstance)
    - description: Given detection rule and target sample,
                   this instance runs the basic Quark analysis
    - params:
        1. SAMPLE_PATH: Target file
        2. ruleInstance: Quark rule object
    - return: quarkResult instance
    - example:

        .. code:: python

            from quark.script import runQuarkAnalysis

            quarkResult = runQuarkAnalysis("sample.apk", ruleInstance)

    """

    global ruleInstance
    global quarkResultInstance

    quark = _getQuark(samplePath)
    quarkResultInstance = QuarkResult(quark, ruleInstance)

    return "Quark analysis completed successfully"


@tool
def getBehaviorOccurList():
    """
    Extracts the behavior occurrence list from quark analysis result.

    Used Quark Script API: quarkResultInstance.behaviorOccurList
    - description: List that stores instances of detected behavior
                   in different part of the target file
    - params: none
    - return: detected behavior instance
    - example:

        .. code:: python

            from quark.script import runQuarkAnalysis

            quarkResult = runQuarkAnalysis("sample.apk", ruleInstance)
            for behavior in quarkResult.behaviorOccurList:
                print(behavior)

    """

    global quarkResultInstance
    global behaviorOccurList

    behaviorOccurList = quarkResultInstance.behaviorOccurList
    return "Behavior occurrence list extracted successfully"


@tool
def getParameterValues():
    """
    Given the behavior occurrence list,
    this instance extracts the parameter values.

    Used Quark Script API: behaviorInstance.getParamValues(none)

    - description: Get parameter values that API1 sends to API2 in the behavior
    - params: none
    - return: python list containing parameter values.
    - example:

        .. code:: python

            from quark.script import runQuarkAnalysis

            quarkResult = runQuarkAnalysis("sample.apk", ruleInstance)
            for behavior in quarkResult.behaviorOccurList:
                paramValues = behavior.getParamValues()
                print(paramValues)
    """

    global behaviorOccurList
    global parameters

    for behavior in behaviorOccurList:
        parameters = behavior.getParamValues()

    return parameters


@tool
def isHardCoded():
    """
    Given the parameter values,
    this instance checks if the parameter values are hard-coded
    and return the hard-coded parameter.

    Used Quark Script API: quarkResultInstance.isHardcoded(argument)
    - description: Check if the argument is hardcoded into the APK.
    - params:
        1. argument: string value that is passed in when a method is invoked
    - return: True/False
    - example:

        .. code:: python

            from quark.script import runQuarkAnalysis

            quarkResult = runQuarkAnalysis("sample.apk", ruleInstance)
            isHardcoded = quarkResult.isHardcoded("hardcodedValue")
            print(isHardcoded)
    """

    global parameters
    global quarkResultInstance

    hardcodedParameters = []
    for parameter in parameters:
        if quarkResultInstance.isHardcoded(parameter):
            hardcodedParameters.append(parameter)

    return hardcodedParameters


@tool
def writeCodeInFile(code: str, pyFile: str):
    """
    Given the code and file name, this instance writes the code in the file.
    """

    with open(pyFile, "w") as file:
        file.write(code)

    return pyFile


@tool
def executeCode(pyFile: str):
    """
    Given the code file, this instance executes the code.
    """

    os.system(f"python {pyFile}")
    return "Code executed successfully"


tools = [
    loadRule,
    runQuarkAnalysis,
    getBehaviorOccurList,
    getParameterValues,
    isHardCoded,
    writeCodeInFile,
    executeCode,
]


llm = ChatOpenAI(model="gpt-4o", temperature=0.2)
llm_with_tools = llm.bind_tools(tools)

prompt = ChatPromptTemplate.from_messages([
    (
        "system",
        "You are very powerful assistant, but don't know current events",
    ),
    ("user", "{input}"),
    MessagesPlaceholder(variable_name="agent_scratchpad"),
])

agent = (
    {
        "input": lambda x: x["input"],
        "agent_scratchpad": lambda x: format_to_openai_tool_messages(
            x["intermediate_steps"]
        ),
    }
    | prompt
    | llm_with_tools
    | OpenAIToolsAgentOutputParser()
)

agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=False)

input_text = input(colored('User Input: ', 'green'))
while input_text.lower() != 'bye':
    if input_text:
        conversation_history.append(input_text)
        response = agent_executor.invoke({
            'input': input_text,
        })
        print()
        print(colored('Agent: ', "cyan"), response['output'])
        print()

        conversation_history.append(response['output'])

        input_text = input(colored('User Input: ', 'green'))
