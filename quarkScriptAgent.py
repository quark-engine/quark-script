import os
import re

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


@tool
def loadRule(rulePath):
    """
    Given a rule path,
    this instance loads a rule from the rule path.
    """

    global ruleInstance
    ruleInstance = Rule(rulePath)

    return "Rule defined successfully"


@tool
def runQuarkAnalysis(samplePath):
    """
    Given detection rule and target sample,
    this instance runs the Quark Analysis.
    """

    global ruleInstance
    global quarkResultInstance

    quark = _getQuark(samplePath)
    quarkResultInstance = QuarkResult(quark, ruleInstance)

    return "Quark analysis completed successfully"


@tool
def getBehaviorOccurList():
    """
    Given the Quark analysis result,
    this instance extracts the behavior occurrence list.
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
    """

    global behaviorOccurList
    global parameters

    for behavior in behaviorOccurList:
        param = behavior.getParamValues()[1]

    parameters = re.findall(r"\((.*?)\)", param)[1]

    return "Parameter values extracted successfully"


@tool
def isHardCoded():
    """
    Given the parameter values,
    this instance checks if the parameter values are hard-coded.
    """

    global parameters
    global quarkResultInstance

    # check parameter values are hard-coded
    if parameters in quarkResultInstance.getAllStrings():
        return parameters

    return False


tools = [
    defineRuleByJson,
    runQuarkAnalysis,
    getBehaviorOccurLise,
    getParameterValues,
    isHardCoded,
]


llm = ChatOpenAI(model="gpt-4o", temperature=0.1)
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
        response = agent_executor.invoke({
            'input': input_text,
        })
        print()
        print(colored('Agent: ', "cyan"), response['output'])
        print()

        input_text = input(colored('User Input: ', 'green'))
