#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import shlex
import solcx
import logging
import eth_utils
import subprocess
import sys
from eth_abi import encode_abi
from eth_abi.exceptions import EncodingTypeError, ValueOutOfBounds, ParseError



from copy import deepcopy, copy


from web3 import Web3
from .settings import LOGGING_LEVEL

def initialize_logger(name):
    logger = logging.getLogger(name)
    logger.title = lambda *a: logger.info(*[bold(x) for x in a])
    logger_error = logger.error
    logger.error = lambda *a: logger_error(*[red(bold(x)) for x in a])
    logger_warning = logger.warning
    logger.warning = lambda *a: logger_warning(*[red(bold(x)) for x in a])
    logger.setLevel(level=LOGGING_LEVEL)
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    return logger

def bold(x):
    return "".join(['\033[1m', x, '\033[0m']) if isinstance(x, str) else x

def red(x):
    return "".join(['\033[91m', x, '\033[0m']) if isinstance(x, str) else x

def code_bool(value: bool):
    return str(int(value)).zfill(64)

def code_uint(value):
    return hex(value).replace("0x", "").zfill(64)

def code_int(value):
    return hex(value).replace("0x", "").zfill(64)

def code_address(value):
    return value.zfill(64)

def code_bytes(value):
    return value.ljust(64, "0")

# def code_type(value, type):
#     if type == "bool":
#         return code_bool(value)
#     elif type.startswith("uint"):
#         return code_uint(value)
#     elif type.startswith("int"):
#         return code_int(value)
#     elif type == "address":
#         return code_address(value)
#     elif type.startswith("bytes"):
#         return code_bytes(value)
#     elif type.startswith('tuple'):
#         print('111111')
#     else:
#         raise Exception()

def run_command(cmd):
    FNULL = open(os.devnull, 'w')
    p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=FNULL)
    return p.communicate()[0]

def compile(solc_version, evm_version, source_code_file):
    out = None
    source_code = ""
    with open(source_code_file, 'r') as file:
        source_code = file.read()
    try:
        if not str(solc_version).startswith("v"):
            solc_version = "v"+str(solc_version.truncate())
        if not solc_version in solcx.get_installed_solc_versions():
            solcx.install_solc(solc_version)
        solcx.set_solc_version(solc_version, True)
        out = solcx.compile_standard({
            'language': 'Solidity',
            'sources': {source_code_file: {'content': source_code}},
            'settings': {
                "optimizer": {
                    "enabled": True,
                    "runs": 200
                },
                "evmVersion": evm_version,
                "outputSelection": {
                    # source_code_file: {
                    #     "*":
                    #         [
                    #             "abi",
                    #             "evm.deployedBytecode",
                    #             "evm.bytecode.object",
                    #             "evm.legacyAssembly",
                    #         ],
                    # }
                    	"*": {
                            "": ["ast"],
                            "*": ["abi", "metadata", "devdoc", "userdoc", "storageLayout", "evm.legacyAssembly", "evm.bytecode", "evm.deployedBytecode", "evm.methodIdentifiers", "evm.gasEstimates", "evm.assembly"]
                        }
                }
            }
        }, allow_paths='.')
    except Exception as e:
        print("Error: Solidity compilation failed!")
        print(e.message)
    return out


def get_interface_from_abi(abi):
    #这里需要增加处理复合数据类型的逻辑
    #print(abi)
    interface = {}
    for field in abi:
        if field['type'] == 'function':
            function_name = field['name']
            function_inputs = []
            signature = function_name + '('
            for i in range(len(field['inputs'])):
                input_type = field['inputs'][i]['type']
                # 处理tuple类型
                if input_type=='tuple':
                    #(xxx,xxx,xxx)的格式
                    real_type='('
                    internal_size=len(field['inputs'][i]['components'])
                    for j in range(internal_size):
                        internal_type=field['inputs'][i]['components'][j]['type']
                        real_type+=internal_type
                        if j < internal_size -1 :
                            real_type+=','
                    real_type+=')'
                    input_type=real_type
                if input_type=='tuple[]':
                    # (xxx,xxx,xxx)的格式
                    real_type='('
                    internal_size=len(field['inputs'][i]['components'])
                    for j in range(internal_size):
                        internal_type=field['inputs'][i]['components'][j]['type']
                        real_type+=internal_type
                        if j < internal_size -1 :
                            real_type+=','
                    real_type+=')'
                    input_type=real_type
                    input_type+='[]'                
                function_inputs.append(input_type)
                signature += input_type
                if i < len(field['inputs']) - 1:
                    signature += ','
            signature += ')'
            hash = Web3.sha3(text=signature)[0:4].hex()
            interface[hash] = function_inputs
        elif field['type'] == 'constructor':
            function_inputs = []
            for i in range(len(field['inputs'])):
                input_type = field['inputs'][i]['type']
                function_inputs.append(input_type)
            interface['constructor'] = function_inputs
    if not "fallback" in interface:
        interface["fallback"] = []
    return interface


def get_function_name_from_abi(abi):
    function_name_list=[]
    for field in abi:
        if field['type'] == 'function':
            function_name = field['name']
            function_name_list.append(function_name)
    return function_name_list

def get_function_name_hash_from_abi(abi):
    interface = {}
    for field in abi:
        if field['type'] == 'function':
            function_name = field['name']
            function_inputs = []
            signature = function_name + '('
            for i in range(len(field['inputs'])):
                input_type = field['inputs'][i]['type']
                # 处理tuple类型
                if input_type=='tuple':
                    #(xxx,xxx,xxx)的格式
                    real_type='('
                    internal_size=len(field['inputs'][i]['components'])
                    for j in range(internal_size):
                        internal_type=field['inputs'][i]['components'][j]['type']
                        real_type+=internal_type
                        if j < internal_size -1 :
                            real_type+=','
                    real_type+=')'
                    input_type=real_type
                if input_type=='tuple[]':
                    # (xxx,xxx,xxx)的格式
                    real_type='('
                    internal_size=len(field['inputs'][i]['components'])
                    for j in range(internal_size):
                        internal_type=field['inputs'][i]['components'][j]['type']
                        real_type+=internal_type
                        if j < internal_size -1 :
                            real_type+=','
                    real_type+=')'
                    input_type=real_type
                    input_type+='[]'                
                function_inputs.append(input_type)
                signature += input_type
                if i < len(field['inputs']) - 1:
                    signature += ','
            signature += ')'
            hash = Web3.sha3(text=signature)[0:4].hex()
            interface[function_name] = hash
    return interface









def has_deposit_function(abi):
    interface={}
    for field in abi:
        if field['type'] == 'function':
            function_name = field['name']
            if "deposit" == function_name:
                function_inputs = []
                signature = function_name + '('
                for i in range(len(field['inputs'])):
                    input_type = field['inputs'][i]['type']
                    # 处理tuple类型
                    if input_type=='tuple':
                        #(xxx,xxx,xxx)的格式
                        real_type='('
                        internal_size=len(field['inputs'][i]['components'])
                        for j in range(internal_size):
                            internal_type=field['inputs'][i]['components'][j]['type']
                            real_type+=internal_type
                            if j < internal_size -1 :
                                real_type+=','
                        real_type+=')'
                        input_type=real_type
                    if input_type=='tuple[]':
                        # (xxx,xxx,xxx)的格式
                        real_type='('
                        internal_size=len(field['inputs'][i]['components'])
                        for j in range(internal_size):
                            internal_type=field['inputs'][i]['components'][j]['type']
                            real_type+=internal_type
                            if j < internal_size -1 :
                                real_type+=','
                        real_type+=')'
                        input_type=real_type
                        input_type+='[]'                
                    function_inputs.append(input_type)
                    signature += input_type
                    if i < len(field['inputs']) - 1:
                        signature += ','
                signature += ')'
                hash = Web3.sha3(text=signature)[0:4].hex()
                interface[hash] = function_inputs
    return interface
                


def get_interface_by_function_name(abi,functionName):
    interface={}
    for field in abi:
        if field['type'] == 'function':
            function_name = field['name']
            if function_name ==  functionName:
                function_inputs = []
                signature = function_name + '('
                for i in range(len(field['inputs'])):
                    input_type = field['inputs'][i]['type']
                    # 处理tuple类型
                    if input_type=='tuple':
                        #(xxx,xxx,xxx)的格式
                        real_type='('
                        internal_size=len(field['inputs'][i]['components'])
                        for j in range(internal_size):
                            internal_type=field['inputs'][i]['components'][j]['type']
                            real_type+=internal_type
                            if j < internal_size -1 :
                                real_type+=','
                        real_type+=')'
                        input_type=real_type
                    if input_type=='tuple[]':
                        # (xxx,xxx,xxx)的格式
                        real_type='('
                        internal_size=len(field['inputs'][i]['components'])
                        for j in range(internal_size):
                            internal_type=field['inputs'][i]['components'][j]['type']
                            real_type+=internal_type
                            if j < internal_size -1 :
                                real_type+=','
                        real_type+=')'
                        input_type=real_type
                        input_type+='[]'                
                    function_inputs.append(input_type)
                    signature += input_type
                    if i < len(field['inputs']) - 1:
                        signature += ','
                signature += ')'
                hash = Web3.sha3(text=signature)[0:4].hex()
                interface[hash] = function_inputs
    return interface    








def has_depositETH_funcion(abi):
    interface={}
    for field in abi:
        if field['type'] == 'function':
            function_name = field['name']
            if "depositETH" == function_name:
                function_inputs = []
                signature = function_name + '('
                for i in range(len(field['inputs'])):
                    input_type = field['inputs'][i]['type']
                    # 处理tuple类型
                    if input_type=='tuple':
                        #(xxx,xxx,xxx)的格式
                        real_type='('
                        internal_size=len(field['inputs'][i]['components'])
                        for j in range(internal_size):
                            internal_type=field['inputs'][i]['components'][j]['type']
                            real_type+=internal_type
                            if j < internal_size -1 :
                                real_type+=','
                        real_type+=')'
                        input_type=real_type
                    if input_type=='tuple[]':
                        # (xxx,xxx,xxx)的格式
                        real_type='('
                        internal_size=len(field['inputs'][i]['components'])
                        for j in range(internal_size):
                            internal_type=field['inputs'][i]['components'][j]['type']
                            real_type+=internal_type
                            if j < internal_size -1 :
                                real_type+=','
                        real_type+=')'
                        input_type=real_type
                        input_type+='[]'                
                    function_inputs.append(input_type)
                    signature += input_type
                    if i < len(field['inputs']) - 1:
                        signature += ','
                signature += ')'
                hash = Web3.sha3(text=signature)[0:4].hex()
                interface[hash] = function_inputs
    return interface    





def get_function_signature_mapping(abi):
    mapping = {}
    for field in abi:
        if field['type'] == 'function':
            function_name = field['name']
            function_inputs = []
            signature = function_name + '('
            for i in range(len(field['inputs'])):
                input_type = field['inputs'][i]['type']
                # 处理tuple类型
                if input_type=='tuple':
                    #(xxx,xxx,xxx)的格式
                    real_type='('
                    internal_size=len(field['inputs'][i]['components'])
                    for j in range(internal_size):
                        internal_type=field['inputs'][i]['components'][j]['type']
                        real_type+=internal_type
                        if j < internal_size -1 :
                            real_type+=','
                    real_type+=')'
                    input_type=real_type
                if input_type=='tuple[]':
                    # (xxx,xxx,xxx)的格式
                    real_type='('
                    internal_size=len(field['inputs'][i]['components'])
                    for j in range(internal_size):
                        internal_type=field['inputs'][i]['components'][j]['type']
                        real_type+=internal_type
                        if j < internal_size -1 :
                            real_type+=','
                    real_type+=')'
                    input_type=real_type
                    input_type+='[]'   
                signature += input_type
                if i < len(field['inputs']) - 1:
                    signature += ','
            signature += ')'
            hash = Web3.sha3(text=signature)[0:4].hex()
            mapping[hash] = signature
    if not "fallback" in mapping:
        mapping["fallback"] = "fallback"
    return mapping

def remove_swarm_hash(bytecode):
    if isinstance(bytecode, str):
        if bytecode.endswith("0029"):
            bytecode = re.sub(r"a165627a7a72305820\S{64}0029$", "", bytecode)
        if bytecode.endswith("0033"):
            bytecode = re.sub(r"5056fe.*?0033$", "5056", bytecode)
    return bytecode

def get_pcs_and_jumpis(bytecode):
    bytecode = bytes.fromhex(remove_swarm_hash(bytecode).replace("0x", ""))
    i = 0
    pcs = []
    jumpis = []
    while i < len(bytecode):
        opcode = bytecode[i]
        pcs.append(i)
        if opcode == 87: # JUMPI
            jumpis.append(hex(i))
        if opcode >= 96 and opcode <= 127: # PUSH
            size = opcode - 96 + 1
            i += size
        i += 1
    if len(pcs) == 0:
        pcs = [0]
    return (pcs, jumpis)

def convert_stack_value_to_int(stack_value):
    if stack_value[0] == int:
        return stack_value[1]
    elif stack_value[0] == bytes:
        return int.from_bytes(stack_value[1], "big")
    else:
        raise Exception("Error: Cannot convert stack value to int. Unknown type: " + str(stack_value[0]))

def convert_stack_value_to_hex(stack_value):
    if stack_value[0] == int:
        return hex(stack_value[1]).replace("0x", "").zfill(64)
    elif stack_value[0] == bytes:
        return stack_value[1].hex().zfill(64)
    else:
        raise Exception("Error: Cannot convert stack value to hex. Unknown type: " + str(stack_value[0]))

def is_fixed(value):
    return isinstance(value, int)

def split_len(seq, length):
    return [seq[i:i + length] for i in range(0, len(seq), length)]

def print_individual_solution_as_transaction(logger, individual_solution, color="", function_signature_mapping={}, transaction_index=None):
    for index, input in enumerate(individual_solution):
        transaction = input["transaction"]
        if not transaction["to"] == None:
            if transaction["data"].startswith("0x"):
                hash = transaction["data"][0:10]
            else:
                hash = transaction["data"][0:8]
            if len(individual_solution) == 1 or (transaction_index != None and transaction_index == 0):
                if hash in function_signature_mapping:
                    logger.title(color+"Transaction - " + function_signature_mapping[hash] + ":")
                else:
                    logger.title(color+"Transaction:")
            else:
                if hash in function_signature_mapping:
                    logger.title(color+"Transaction " + str(index + 1) + " - " + function_signature_mapping[hash] + ":")
                else:
                    logger.title(color+"Transaction " + str(index + 1) + ":")
            logger.title(color+"-----------------------------------------------------")
            logger.title(color+"From:      " + transaction["from"])
            logger.title(color+"To:        " + str(transaction["to"]))
            logger.title(color+"Value:     " + str(transaction["value"]) + " Wei")
            logger.title(color+"Gas Limit: " + str(transaction["gaslimit"]))
            i = 0
            for data in split_len("0x" + transaction["data"].replace("0x", ""), 42):
                if i == 0:
                    logger.title(color+"Input:     " + str(data))
                else:
                    logger.title(color+"           " + str(data))
                i += 1
            logger.title(color+"-----------------------------------------------------")
            if transaction_index != None and index + 1 > transaction_index:
                break

def normalize_32_byte_hex_address(value):
    as_bytes = eth_utils.to_bytes(hexstr=value)
    return eth_utils.to_normalized_address(as_bytes[-20:])





def parse_init_json_and_exec(init_json,interface_name,contract,account,env,interface) :
    item = init_json.items()
    tx_param = []
    for k,v in item:
        funcname = k
        # 获取到function hash
        tx_param.append(interface_name[funcname])

        paramTypeList = []
        valueList = []
        individual = []
        for pkey,pvalue in v.items():
            for type,value in pvalue.items():
                # print(type)
                # print(value['type'])
                paramType = value['type']
                paramTypeList.append(paramType)

                if paramType.startswith("address"):
                    tx_param.append(value['value'])
                    valueList.append(value['value'])
                elif paramType.startswith("uint"):
                    tx_param.append(int(value['value']))
                    valueList.append(int(value['value']))                    
                elif paramType.startswith("bytes1") or \
                    paramType.startswith("bytes2") or \
                    paramType.startswith("bytes3") or \
                    paramType.startswith("bytes4") or \
                    paramType.startswith("bytes5") or \
                    paramType.startswith("bytes6") or \
                    paramType.startswith("bytes7") or \
                    paramType.startswith("bytes8") or \
                    paramType.startswith("bytes9") or \
                    paramType.startswith("bytes10") or \
                    paramType.startswith("bytes11") or \
                    paramType.startswith("bytes12") or \
                    paramType.startswith("bytes13") or \
                    paramType.startswith("bytes14") or \
                    paramType.startswith("bytes15") or \
                    paramType.startswith("bytes16") or \
                    paramType.startswith("bytes17") or \
                    paramType.startswith("bytes18") or \
                    paramType.startswith("bytes19") or \
                    paramType.startswith("bytes20") or \
                    paramType.startswith("bytes21") or \
                    paramType.startswith("bytes22") or \
                    paramType.startswith("bytes23") or \
                    paramType.startswith("bytes24") or \
                    paramType.startswith("bytes25") or \
                    paramType.startswith("bytes26") or \
                    paramType.startswith("bytes27") or \
                    paramType.startswith("bytes28") or \
                    paramType.startswith("bytes29") or \
                    paramType.startswith("bytes30") or \
                    paramType.startswith("bytes31") or \
                    paramType.startswith("bytes32"):
                        length = int(paramType.replace("bytes", "").split("[")[0])
                        tx_param.append(bytearray(bytes.fromhex(value['value'][2:])))
                        valueList.append(bytearray(bytes.fromhex(value['value'][2:])))
                

            individual.append({
                "account": account[0],
                "contract": contract,
                "amount": 0,
                "arguments": tx_param,
                "blocknumber": None,
                "timestamp": None,
                "gaslimit": 4500000,
                "returndatasize": dict()
            })

            individual[-1]["call_return"] = None

            individual[-1]["extcodesize"] = None

            individual[-1]["returndatasize"] = None



            solution = decode(individual,interface)
                


            # print(value['value'])

            execution_function(solution,env) 

        return paramTypeList,valueList


        
# def contruct_tx():



# def exec_tx():


def decode(individual,interface):
    solution = []
    for i in range(len(individual)):
        transaction = {}
        transaction["from"] = copy(individual[i]["account"])
        transaction["to"] = copy(individual[i]["contract"])
        transaction["value"] = copy(individual[i]["amount"])
        transaction["gaslimit"] = copy(individual[i]["gaslimit"])
        transaction["data"] = get_transaction_data_from_chromosome(individual,i,interface)

        block = {}
        if "timestamp" in individual[i] and individual[i]["timestamp"] is not None:
            block["timestamp"] = copy(individual[i]["timestamp"])
        if "blocknumber" in individual[i] and individual[i]["blocknumber"] is not None:
            block["blocknumber"] = copy(individual[i]["blocknumber"])

        global_state = {}
        if "balance" in individual[i] and individual[i]["balance"] is not None:
            global_state["balance"] = copy(individual[i]["balance"])
        if "call_return" in individual[i] and individual[i]["call_return"] is not None\
                and len(individual[i]["call_return"]) > 0:
            global_state["call_return"] = copy(individual[i]["call_return"])
        if "extcodesize" in individual[i] and individual[i]["extcodesize"] is not None\
                and len(individual[i]["extcodesize"]) > 0:
            global_state["extcodesize"] = copy(individual[i]["extcodesize"])

        environment = {}
        if "returndatasize" in individual[i] and individual[i]["returndatasize"] is not None:
            environment["returndatasize"] = copy(individual[i]["returndatasize"])

        input = {"transaction":transaction, "block" : block, "global_state" : global_state, "environment": environment}
        solution.append(input)
    return solution






def get_transaction_data_from_chromosome(individual,i,interface):
    data = ""
    arguments = []
    function = None
    for j in range(len(individual[i]["arguments"])):
        if not type(individual[i]["arguments"][j]) is bytearray and \
                not type(individual[i]["arguments"][j]) is list and \
                not type(individual[i]["arguments"][j]) is tuple and \
                individual[i]["arguments"][j] in interface:
            function = individual[i]["arguments"][j]
            data += individual[i]["arguments"][j]
        else:
            arguments.append(individual[i]["arguments"][j])
    try:
        argument_types = [argument_type.replace(" storage", "").replace(" memory", "") for argument_type in interface[function]]                 
        data += encode_abi(argument_types, arguments).hex()
    except Exception as e:
        sys.exit(-6)


    return data



def execution_function(solution,env):
    for transaction_index, test in enumerate(solution):
        transaction = test["transaction"]
        _function_hash = transaction["data"][:10] if transaction["data"].startswith("0x") else transaction["data"][:8]

        result = env.instrumented_evm.deploy_transaction(test)

        # print(result)
