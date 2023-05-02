#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import solcx
import random
import logging
import argparse

from eth_utils import encode_hex, decode_hex, to_canonical_address
from z3 import Solver

from evm import InstrumentedEVM
from detectors import DetectorExecutor
from engine import EvolutionaryFuzzingEngine
from engine.components import Generator, Individual, Population
from engine.analysis import SymbolicTaintAnalyzer
from engine.analysis import ExecutionTraceAnalyzer
from engine.environment import FuzzingEnvironment
from engine.operators import LinearRankingSelection
from engine.operators import DataDependencyLinearRankingSelection
from engine.operators import Crossover
from engine.operators import DataDependencyCrossover
from engine.operators import Mutation
from engine.fitness import fitness_function

from utils import settings
from utils.source_map import SourceMap
from utils.utils import initialize_logger, compile, get_interface_from_abi, get_function_name_from_abi, get_pcs_and_jumpis, get_function_signature_mapping,has_deposit_function,has_depositETH_funcion,get_interface_by_function_name,parse_init_json_and_exec,get_function_name_hash_from_abi

from utils.control_flow_graph import ControlFlowGraph

class Fuzzer:
    # 新增了token contract 的参数
    # 新增token代码
    def __init__(self, contract_name, abi, deployment_bytecode, runtime_bytecode,
                token_contract_name,token_abi,token_deployment_bytecode,
                attck_contract_name, attack_abi,attack_deployment_bytecode, 
                test_instrumented_evm, blockchain_state, solver, args, seed, 
                source_map=None,attack_contract_source_map=None,token_contract_source_map=None,
                token=None,signatory=None,initJson=None):
        global logger
        logger = initialize_logger("Fuzzer  ")
        logger.title("Fuzzing contract %s", contract_name)

        cfg = ControlFlowGraph()
        cfg.build(runtime_bytecode, settings.EVM_VERSION)

        self.contract_name = contract_name
        self.interface = get_interface_from_abi(abi)

        # 新增deposit 和 depositETH的 interface 
        self.deposit_interface = has_deposit_function(abi)

        self.depositETH_interface = has_depositETH_funcion(abi)

        self.deployement_bytecode = deployment_bytecode

        self.abi=abi


        self.attack_address=""
        #print(self.deployement_bytecode)  
        # token 合约的接口 （abi）
        # print(token_abi)
        self.token_contract_name=token_contract_name
        self.token_interface=get_interface_from_abi(token_abi)
        self.token_deployment_bytecode = token_deployment_bytecode
        self.token_interface_name=get_function_name_from_abi(token_abi)

        # 新增token数组
        self.token = token

        # 新增signatory  
        self.signatory = signatory

        # 新增init的执行
        self.initJson = initJson

        # 新增被测合约的interface_name
        self.interface_name = get_function_name_hash_from_abi(abi)

        # attack 合约的接口
        self.attck_contract_name=attck_contract_name
        self.attack_interface=get_interface_from_abi(attack_abi),
        self.attack_deployment_bytecode = attack_deployment_bytecode

        self.blockchain_state = blockchain_state
        self.instrumented_evm = test_instrumented_evm
        self.solver = solver
        self.args = args

        # Get some overall metric on the code
        self.overall_pcs, self.overall_jumpis = get_pcs_and_jumpis(runtime_bytecode)

        # Initialize results
        self.results = {"errors": {}}


        # Initialize fuzzing environment
        self.env = FuzzingEnvironment(instrumented_evm=self.instrumented_evm,
                                      contract_name=self.contract_name,
                                      solver=self.solver,
                                      results=self.results,
                                      symbolic_taint_analyzer=SymbolicTaintAnalyzer(),
                                      detector_executor=DetectorExecutor(source_map,attack_contract_source_map,token_contract_source_map, self.token_interface_name,get_function_signature_mapping(abi)),
                                      interface=self.interface,
                                      overall_pcs=self.overall_pcs,
                                      overall_jumpis=self.overall_jumpis,
                                      len_overall_pcs_with_children=0,
                                      other_contracts = list(),
                                      args=args,
                                      seed=seed,
                                      cfg=cfg,
                                      abi=abi)

    def run(self):
        contract_address = None
        
        # 新增token 合约的地址 (multichain)
        token_contract_address = None
        attack_contract_address = None 
        self.instrumented_evm.create_fake_accounts()
        self.env.detector_executor.contract_dict={}


        paramTypeList = []
        valueList = []

        if self.args.source:
            for transaction in self.blockchain_state:
                if transaction['from'].lower() not in self.instrumented_evm.accounts:
                    self.instrumented_evm.accounts.append(self.instrumented_evm.create_fake_account(transaction['from']))

                if not transaction['to']:
                    result = self.instrumented_evm.deploy_contract(transaction['from'], transaction['input'], int(transaction['value']), int(transaction['gas']), int(transaction['gasPrice']))
                    if result.is_error:
                        logger.error("Problem while deploying contract %s using account %s. Error message: %s", self.contract_name, transaction['from'], result._error)
                        sys.exit(-2)
                    else:
                        contract_address = encode_hex(result.msg.storage_address)
                        self.instrumented_evm.accounts.append(contract_address)
                        self.env.nr_of_transactions += 1
                        logger.debug("Contract deployed at %s", contract_address)
                        self.env.other_contracts.append(to_canonical_address(contract_address))
                        cc, _ = get_pcs_and_jumpis(self.instrumented_evm.get_code(to_canonical_address(contract_address)).hex())
                        self.env.len_overall_pcs_with_children += len(cc)
                else:
                    input = {}
                    input["block"] = {}
                    input["transaction"] = {
                        "from": transaction["from"],
                        "to": transaction["to"],
                        "gaslimit": int(transaction["gas"]),
                        "value": int(transaction["value"]),
                        "data": transaction["input"]
                    }
                    input["global_state"] = {}
                    out = self.instrumented_evm.deploy_transaction(input, int(transaction["gasPrice"]))

            if "constructor" in self.interface:
                del self.interface["constructor"]

            
            # 新增token合约地址
            if not token_contract_address:
                if "constructor" not in self.token_interface:
                    result = self.instrumented_evm.deploy_contract(self.instrumented_evm.accounts[0],self.token_deployment_bytecode)
                    token_contract_address = encode_hex(result.msg.storage_address)
                    #print("token_contract_address = ",token_contract_address)
                    self.instrumented_evm.token_contract_acount.append(token_contract_address)
                    self.env.nr_of_transactions+=1
                    logger.debug("token contract deployed at %s", token_contract_address)                    

            # 新增攻击合约
            if not attack_contract_address:
                if "constructor" not in self.attack_interface:    
                    result = self.instrumented_evm.deploy_contract(self.instrumented_evm.accounts[0],self.attack_deployment_bytecode)
                    attack_contract_address = encode_hex(result.msg.storage_address)
                    #print("attack_contract_address = ",attack_contract_address)
                    self.instrumented_evm.attack_contract_accout.append(attack_contract_address)
                    self.env.nr_of_transactions+=1
                    logger.debug("attack contract deployed at %s", attack_contract_address)   


            if not contract_address:
                if "constructor" not in self.interface:                  
                    result = self.instrumented_evm.deploy_contract(self.instrumented_evm.accounts[0], self.deployement_bytecode)
                    if result.is_error:
                        logger.error("Problem while deploying contract %s using account %s. Error message: %s", self.contract_name, self.instrumented_evm.accounts[0], result._error)
                        sys.exit(-2)
                    else:    
                        contract_address = encode_hex(result.msg.storage_address)
                        #print("contract_address = ",contract_address)
                        self.instrumented_evm.accounts.append(contract_address)
                        self.env.nr_of_transactions += 1
                        logger.debug("Contract deployed at %s", contract_address)

            # 输出account的地址
            # print("account contract address ",self.instrumented_evm.token_contract_acount)

            if self.initJson!=None:
            # 执行initJson的函数
                paramTypeList,valueList = parse_init_json_and_exec(self.initJson,self.interface_name,contract_address,self.instrumented_evm.accounts,self.env,self.interface)
            #     # contruct_tx()
            #     # exec_tx()


            if contract_address in self.instrumented_evm.accounts:
                self.instrumented_evm.accounts.remove(contract_address)

            self.env.overall_pcs, self.env.overall_jumpis = get_pcs_and_jumpis(self.instrumented_evm.get_code(to_canonical_address(contract_address)).hex())

        if self.args.abi:
            contract_address = self.args.contract

        self.env.detector_executor.contract_dict[token_contract_address]=self.token_interface_name

        self.instrumented_evm.create_snapshot()
        # print(self.instrumented_evm.accounts)
        # ['0xcafebabecafebabecafebabecafebabecafebabe', '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef']
        # print(self.instrumented_evm.token_contract_acount)
        # ['0x2c5e8a3b3aad9df32339409534e64dfcabcd3a65']

        tokenHandlerFunc = []
        # 做 Name  和 hash  的dict
        tokenHandlerFuncHash = {}

        # 获取token的存款函数
        # token type 和 对应的function hash
        if self.token != None:
            for i in range(len(self.token["function"]["name"])):
                tokenHandlerFunc.append(self.token["function"]["name"][i])
                tokenHandlerFuncHash[self.token["function"]["name"][i]] = get_interface_by_function_name(self.abi,self.token["function"]["name"][i])
            self.env.token_type_check=True
        # 传递deposit 的 functionhash 和 depositETH 的function hash 
            generator = Generator(interface=self.interface,
                                bytecode=self.deployement_bytecode,
                                accounts=self.instrumented_evm.accounts,
                                token_contract_acount=self.instrumented_evm.token_contract_acount,
                                attack_contract_account=self.instrumented_evm.attack_contract_accout,
                                contract=contract_address,
                                # 新增 depositETH_interface 和 deposit_interface 
                                deposit_interface = self.deposit_interface,
                                depositETH_interface = self.depositETH_interface,
                                tokenHandlerFuncHash = tokenHandlerFuncHash,
                                tokens = self.token["token"],
                                paramTypeList = paramTypeList,
                                valueList = valueList
                                )
        
        
        falseSignatory=[]
        # 获取signatory
        if self.signatory!=None:
            signatoryIndex = self.signatory["index"]
            signatoryType = self.signatory["type"]
            for i in range (len(self.signatory["false"]["signatorys"])):
                falseSignatory.append(self.signatory["false"]["signatorys"][i])

            self.env.signatory_check = True
            # false signatory 产生
            generator = Generator(interface=self.interface,
                                bytecode=self.deployement_bytecode,
                                accounts=self.instrumented_evm.accounts,
                                token_contract_acount=self.instrumented_evm.token_contract_acount,
                                attack_contract_account=self.instrumented_evm.attack_contract_accout,
                                contract=contract_address,
                                # 新增 depositETH_interface 和 deposit_interface 
                                deposit_interface = self.deposit_interface,
                                depositETH_interface = self.depositETH_interface,
                                tokenHandlerFuncHash = tokenHandlerFuncHash,
                                falseSignatorys = falseSignatory,
                                signatoryIndex = signatoryIndex,
                                signatoryType = signatoryType,
                                )



        if self.token==None and self.signatory==None:
            generator = Generator(interface=self.interface,
                                bytecode=self.deployement_bytecode,
                                accounts=self.instrumented_evm.accounts,
                                token_contract_acount=self.instrumented_evm.token_contract_acount,
                                attack_contract_account=self.instrumented_evm.attack_contract_accout,
                                contract=contract_address,
                                # 新增 depositETH_interface 和 deposit_interface 
                                deposit_interface = self.deposit_interface,
                                depositETH_interface = self.depositETH_interface,
                                tokenHandlerFuncHash = tokenHandlerFuncHash,
                                paramTypeList = paramTypeList,
                                valueList = valueList
                                # tokens = self.token["token"]
                                )

        # 新增传递generator
        self.env.detector_executor.generator =generator


        # Create initial population
        size = 2 * len(self.interface)
        population = Population(indv_template=Individual(generator=generator),
                                indv_generator=generator,
                                size=settings.POPULATION_SIZE if settings.POPULATION_SIZE else size).init()

        # Create genetic operators
        if self.args.data_dependency:
            selection = DataDependencyLinearRankingSelection(env=self.env)
            crossover = DataDependencyCrossover(pc=settings.PROBABILITY_CROSSOVER, env=self.env)
            mutation = Mutation(pm=settings.PROBABILITY_MUTATION)
        else:
            selection = LinearRankingSelection()
            crossover = Crossover(pc=settings.PROBABILITY_CROSSOVER)
            mutation = Mutation(pm=settings.PROBABILITY_MUTATION)

        # Create and run our evolutionary fuzzing engine
        engine = EvolutionaryFuzzingEngine(population=population, selection=selection, crossover=crossover, mutation=mutation, mapping=get_function_signature_mapping(self.env.abi))
        engine.fitness_register(lambda x: fitness_function(x, self.env))
        engine.analysis.append(ExecutionTraceAnalyzer(self.env))

        self.env.execution_begin = time.time()
        self.env.population = population

        engine.run(ng=settings.GENERATIONS)

        if self.env.args.cfg:
            if self.env.args.source:
                self.env.cfg.save_control_flow_graph(os.path.splitext(self.env.args.source)[0]+'-'+self.contract_name, 'pdf')
            elif self.env.args.abi:
                self.env.cfg.save_control_flow_graph(os.path.join(os.path.dirname(self.env.args.abi), self.contract_name), 'pdf')

        self.instrumented_evm.reset()

def main():
    print_logo()
    args = launch_argument_parser()

    logger = initialize_logger("Main    ")

    # Check if contract has already been analyzed
    if args.results and os.path.exists(args.results):
        os.remove(args.results)
        logger.info("Contract "+str(args.source)+" has already been analyzed: "+str(args.results))
        sys.exit(0)

    # Initializing random
    if args.seed:
        seed = args.seed
        if not "PYTHONHASHSEED" in os.environ:
            logger.debug("Please set PYTHONHASHSEED to '1' for Python's hash function to behave deterministically.")
    else:
        seed = random.random()
    random.seed(seed)
    logger.title("Initializing seed to %s", seed)

    # Initialize EVM
    instrumented_evm = InstrumentedEVM(settings.RPC_HOST, settings.RPC_PORT)
    instrumented_evm.set_vm_by_name(settings.EVM_VERSION)

    # Create Z3 solver instance
    solver = Solver()
    solver.set("timeout", settings.SOLVER_TIMEOUT)

    # Parse blockchain state if provided
    blockchain_state = []
    if args.blockchain_state:
        if args.blockchain_state.endswith(".json"):
            with open(args.blockchain_state) as json_file:
                for line in json_file.readlines():
                    blockchain_state.append(json.loads(line))
        elif args.blockchain_state.isnumeric():
            settings.BLOCK_HEIGHT = int(args.blockchain_state)
            instrumented_evm.set_vm(settings.BLOCK_HEIGHT)
        else:
            logger.error("Unsupported input file: " + args.blockchain_state)
            sys.exit(-1)


    token_contract=""
    token_contract_name=None
    token_contract_source_map=None
    # 先编译token合约
    if args.token_contract:
        if args.source.endswith(".sol"):
            token_compiler_output = compile(args.token_solc, settings.EVM_VERSION, args.token_contract)
            if not token_compiler_output:
                logger.error("No compiler output for: " + args.token_contract)
                sys.exit(-1)
        for contract_name, contract in token_compiler_output['contracts'][args.token_contract].items():
            token_contract=contract
            token_contract_name=contract_name
            token_contract_source_map=SourceMap(':'.join([args.token_contract, contract_name]), token_compiler_output)
    # token_contract 是 token的合约
    # print(token_contract_name)
        

    token = None
    if args.token_type:
        with open(args.token_type) as json_file:
            token = json.load(json_file)


    signatory = None
    # 新增签名参数
    if args.signatory:
        with open(args.signatory) as json_file:
            signatory = json.load(json_file)


    initJson = None
    if args.init_json:
        with open(args.init_json) as json_file:
            initJson = json.load(json_file)



    attack_contract=""
    attck_contract_name=None
    attack_contract_source_map=None
    # 编译attack 合约
    if args.attack_contract:
        if args.source.endswith(".sol"):
            attack_compiler_output = compile(args.attack_solc, settings.EVM_VERSION, args.attack_contract)
            # print(attack_compiler_output)
            if not attack_compiler_output:
                logger.error("No compiler output for: " + args.attack_contract)
                sys.exit(-1)
        for contract_name, contract in attack_compiler_output['contracts'][args.attack_contract].items():
            if contract_name==args.attack_contract_contract:
                attack_contract=contract
                attck_contract_name=contract_name 
                attack_contract_source_map=SourceMap(':'.join([args.attack_contract, contract_name]), attack_compiler_output)
            # if contract_name=="Exploit":
            #     attack_contract=contract
            #     attck_contract_name=contract_name 
            #     attack_contract_source_map=SourceMap(':'.join([args.attack_contract, contract_name]), attack_compiler_output)
            # if contract_name=="ERC20Handler":
            #     attack_contract=contract
            #     attck_contract_name=contract_name 
            #     attack_contract_source_map=SourceMap(':'.join([args.attack_contract, contract_name]), attack_compiler_output)

    # print(attack_contract['evm']['bytecode']['object'])
    # Compile source code to get deployment bytecode, runtime bytecode and ABI
    if args.source:
        if args.source.endswith(".sol"):
            compiler_output = compile(args.solc_version, settings.EVM_VERSION, args.source)
            if not compiler_output:
                logger.error("No compiler output for: " + args.source)
                sys.exit(-1)
            for contract_name, contract in compiler_output['contracts'][args.source].items():
                if args.contract and contract_name != args.contract:
                    continue
                if contract['abi'] and contract['evm']['bytecode']['object'] and contract['evm']['deployedBytecode']['object']:
                    contract_source_map = SourceMap(':'.join([args.source, contract_name]), compiler_output)
                    Fuzzer(contract_name, contract["abi"], contract['evm']['bytecode']['object'],contract['evm']['deployedBytecode']['object'],
                            token_contract_name, token_contract["abi"], token_contract['evm']['bytecode']['object'],
                            attck_contract_name, 
                            attack_contract["abi"], 
                            attack_contract['evm']['bytecode']['object'],                           
                            instrumented_evm, blockchain_state, solver, args, seed, 
                            contract_source_map,attack_contract_source_map,token_contract_source_map,
                            token,signatory,initJson).run()
                    # Fuzzer(contract_name, contract["abi"], contract['evm']['bytecode']['object'],contract['evm']['deployedBytecode']['object'],instrumented_evm, blockchain_state, solver, args, seed, source_map).run()

        else:
            logger.error("Unsupported input file: " + args.source)
            sys.exit(-1)
    # todo : Fuzzer 参数 需要改一下
    if args.abi:
        with open(args.abi) as json_file:
            abi = json.load(json_file)
            runtime_bytecode = instrumented_evm.get_code(to_canonical_address(args.contract)).hex()
            Fuzzer(args.contract, abi, None, runtime_bytecode, instrumented_evm, blockchain_state, solver, args, seed).run()

def launch_argument_parser():
    parser = argparse.ArgumentParser()

    # Contract parameters
    group1 = parser.add_mutually_exclusive_group(required=True)
    group1.add_argument("-s", "--source", type=str,
                        help="Solidity smart contract source code file (.sol).")
    group1.add_argument("-a", "--abi", type=str,
                        help="Smart contract ABI file (.json).")
    
    # 有别的合约依赖，所以需要指定别的合约，然后部署上去
    # 部署token合约，需要改一下变量名
    parser.add_argument("--token_contract",type=str,
                        help="token contract need.")
    
    
    # 别的合约可能有多个版本，所以需要指定一下
    # todo 部署token合约，需要改一下变量名
    parser.add_argument("--token_solc",type=str,
                        help="Solidity compiler version")

    # 部署攻击合约
    parser.add_argument("--attack_contract",type=str,
                        help="attack contract need.")
    
    parser.add_argument("--attack_contract_contract",type=str,
                        help="attack contract contract")

    # token 的数组地址
    # ERC20 
    parser.add_argument("--ERC20_contract",type=str)
    # not ERC20
    parser.add_argument("--other_contract",type=str)
    

    # token的json 文件的路径
    parser.add_argument("--token_type",type=str,
                        help="token type need json file")



    # 攻击合约的版本
    parser.add_argument("--attack_solc",type=str,
                        help="attack contract compiler version")
    
    # 签名的参数
    parser.add_argument("--signatory",type=str,
                        help="signatory 的参数指定")
    
    # 完成初始化json的解析
    parser.add_argument("--init_json",type=str,
                        help="初始化json文件")    

    #group2 = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument("-c", "--contract", type=str,
                        help="Contract name to be fuzzed (if Solidity source code file provided) or blockchain contract address (if ABI file provided).")

    parser.add_argument("-b", "--blockchain-state", type=str,
                        help="Initialize fuzzer with a blockchain state by providing a JSON file (if Solidity source code file provided) or a block number (if ABI file provided).")

    # Compiler parameters
    parser.add_argument("--solc", help="Solidity compiler version (default '" + str(
        solcx.get_solc_version()) + "'). Installed compiler versions: " + str(solcx.get_installed_solc_versions()) + ".",
                        action="store", dest="solc_version", type=str)
    parser.add_argument("--evm", help="Ethereum VM (default '" + str(
        settings.EVM_VERSION) + "'). Available VM's: 'homestead', 'byzantium' or 'petersburg'.", action="store",
                        dest="evm_version", type=str)

    # Evolutionary parameters
    group3 = parser.add_mutually_exclusive_group(required=False)
    group3.add_argument("-g", "--generations",
                        help="Number of generations (default " + str(settings.GENERATIONS) + ").", action="store",
                        dest="generations", type=int)
    group3.add_argument("-t", "--timeout",
                        help="Number of seconds for fuzzer to stop.", action="store",
                        dest="global_timeout", type=int)
    parser.add_argument("-n", "--population-size",
                        help="Size of the population.", action="store",
                        dest="population_size", type=int)
    parser.add_argument("-pc", "--probability-crossover",
                        help="Size of the population.", action="store",
                        dest="probability_crossover", type=float)
    parser.add_argument("-pm", "--probability-mutation",
                        help="Size of the population.", action="store",
                        dest="probability_mutation", type=float)

    # Miscellaneous parameters
    parser.add_argument("-r", "--results", type=str, help="Folder or JSON file where results should be stored.")
    parser.add_argument("--seed", type=float, help="Initialize the random number generator with a given seed.")
    parser.add_argument("--cfg", help="Build control-flow graph and highlight code coverage.", action="store_true")
    parser.add_argument("--rpc-host", help="Ethereum client RPC hostname.", action="store", dest="rpc_host", type=str)
    parser.add_argument("--rpc-port", help="Ethereum client RPC port.", action="store", dest="rpc_port", type=int)

    parser.add_argument("--data-dependency",
                        help="Disable/Enable data dependency analysis: 0 - Disable, 1 - Enable (default: 1)", action="store",
                        dest="data_dependency", type=int)
    parser.add_argument("--constraint-solving",
                        help="Disable/Enable constraint solving: 0 - Disable, 1 - Enable (default: 1)", action="store",
                        dest="constraint_solving", type=int)
    parser.add_argument("--environmental-instrumentation",
                        help="Disable/Enable environmental instrumentation: 0 - Disable, 1 - Enable (default: 1)", action="store",
                        dest="environmental_instrumentation", type=int)
    parser.add_argument("--max-individual-length",
                        help="Maximal length of an individual (default: " + str(settings.MAX_INDIVIDUAL_LENGTH) + ")", action="store",
                        dest="max_individual_length", type=int)
    parser.add_argument("--max-symbolic-execution",
                        help="Maximum number of symbolic execution calls before restting population (default: " + str(settings.MAX_SYMBOLIC_EXECUTION) + ")", action="store",
                        dest="max_symbolic_execution", type=int)

    version = "ConFuzzius - Version 0.0.2 - "
    version += "\"By three methods we may learn wisdom:\n"
    version += "First, by reflection, which is noblest;\n"
    version += "Second, by imitation, which is easiest;\n"
    version += "And third by experience, which is the bitterest.\"\n"
    parser.add_argument("-v", "--version", action="version", version=version)

    args = parser.parse_args()

    if not args.contract:
        args.contract = ""

    if args.source and args.contract.startswith("0x"):
        parser.error("--source requires --contract to be a name, not an address.")
    if args.source and args.blockchain_state and args.blockchain_state.isnumeric():
        parser.error("--source requires --blockchain-state to be a file, not a number.")

    if args.abi and not args.contract.startswith("0x"):
        parser.error("--abi requires --contract to be an address, not a name.")
    if args.abi and args.blockchain_state and not args.blockchain_state.isnumeric():
        parser.error("--abi requires --blockchain-state to be a number, not a file.")

    if args.evm_version:
        settings.EVM_VERSION = args.evm_version
    if not args.solc_version:
        args.solc_version = solcx.get_solc_version()
    if args.generations:
        settings.GENERATIONS = args.generations
    if args.global_timeout:
        settings.GLOBAL_TIMEOUT = args.global_timeout
    if args.population_size:
        settings.POPULATION_SIZE = args.population_size
    if args.probability_crossover:
        settings.PROBABILITY_CROSSOVER = args.probability_crossover
    if args.probability_mutation:
        settings.PROBABILITY_MUTATION = args.probability_mutation

    if args.data_dependency == None:
        args.data_dependency = 1
    if args.constraint_solving == None:
        args.constraint_solving = 1
    if args.environmental_instrumentation == None:
        args.environmental_instrumentation = 1

    if args.environmental_instrumentation == 1:
        settings.ENVIRONMENTAL_INSTRUMENTATION = True
    elif args.environmental_instrumentation == 0:
        settings.ENVIRONMENTAL_INSTRUMENTATION = False

    if args.max_individual_length:
        settings.MAX_INDIVIDUAL_LENGTH = args.max_individual_length
    if args.max_symbolic_execution:
        settings.MAX_SYMBOLIC_EXECUTION = args.max_symbolic_execution

    if args.abi:
        settings.REMOTE_FUZZING = True

    if args.rpc_host:
        settings.RPC_HOST = args.rpc_host
    if args.rpc_port:
        settings.RPC_PORT = args.rpc_port

    return args

def print_logo():
    print("")
    print("     ______            ______                _           ")
    print("    / ____/___  ____  / ____/_  __________  (_)_  _______")
    print("   / /   / __ \/ __ \/ /_  / / / /_  /_  / / / / / / ___/")
    print("  / /___/ /_/ / / / / __/ / /_/ / / /_/ /_/ / /_/ (__  ) ")
    print("  \____/\____/_/ /_/_/    \__,_/ /___/___/_/\__,_/____/  ")
    print("")

if '__main__' == __name__:
    main()
