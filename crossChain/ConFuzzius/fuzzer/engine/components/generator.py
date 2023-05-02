#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import collections
import string

from utils import settings
from utils.utils import *

UINT_MAX = {
    1: int("0xff", 16),
    2: int("0xffff", 16),
    3: int("0xffffff", 16),
    4: int("0xffffffff", 16),
    5: int("0xffffffffff", 16),
    6: int("0xffffffffffff", 16),
    7: int("0xffffffffffffff", 16),
    8: int("0xffffffffffffffff", 16),
    9: int("0xffffffffffffffffff", 16),
    10: int("0xffffffffffffffffffff", 16),
    11: int("0xffffffffffffffffffffff", 16),
    12: int("0xffffffffffffffffffffffff", 16),
    13: int("0xffffffffffffffffffffffffff", 16),
    14: int("0xffffffffffffffffffffffffffff", 16),
    15: int("0xffffffffffffffffffffffffffffff", 16),
    16: int("0xffffffffffffffffffffffffffffffff", 16),
    17: int("0xffffffffffffffffffffffffffffffffff", 16),
    18: int("0xffffffffffffffffffffffffffffffffffff", 16),
    19: int("0xffffffffffffffffffffffffffffffffffffff", 16),
    20: int("0xffffffffffffffffffffffffffffffffffffffff", 16),
    21: int("0xffffffffffffffffffffffffffffffffffffffffff", 16),
    22: int("0xffffffffffffffffffffffffffffffffffffffffffff", 16),
    23: int("0xffffffffffffffffffffffffffffffffffffffffffffff", 16),
    24: int("0xffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    25: int("0xffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    26: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    27: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    28: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    29: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    30: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    31: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    32: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
}

INT_MAX = {
    1: int("0x7f", 16),
    2: int("0x7fff", 16),
    3: int("0x7fffff", 16),
    4: int("0x7fffffff", 16),
    5: int("0x7fffffffff", 16),
    6: int("0x7fffffffffff", 16),
    7: int("0x7fffffffffffff", 16),
    8: int("0x7fffffffffffffff", 16),
    9: int("0x7fffffffffffffffff", 16),
    10: int("0x7fffffffffffffffffff", 16),
    11: int("0x7fffffffffffffffffffff", 16),
    12: int("0x7fffffffffffffffffffffff", 16),
    13: int("0x7fffffffffffffffffffffffff", 16),
    14: int("0x7fffffffffffffffffffffffffff", 16),
    15: int("0x7fffffffffffffffffffffffffffff", 16),
    16: int("0x7fffffffffffffffffffffffffffffff", 16),
    17: int("0x7fffffffffffffffffffffffffffffffff", 16),
    18: int("0x7fffffffffffffffffffffffffffffffffff", 16),
    19: int("0x7fffffffffffffffffffffffffffffffffffff", 16),
    20: int("0x7fffffffffffffffffffffffffffffffffffffff", 16),
    21: int("0x7fffffffffffffffffffffffffffffffffffffffff", 16),
    22: int("0x7fffffffffffffffffffffffffffffffffffffffffff", 16),
    23: int("0x7fffffffffffffffffffffffffffffffffffffffffffff", 16),
    24: int("0x7fffffffffffffffffffffffffffffffffffffffffffffff", 16),
    25: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    26: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    27: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    28: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    29: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    30: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    31: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    32: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
}

INT_MIN = {
    1: int("-0x80", 16),
    2: int("-0x8000", 16),
    3: int("-0x800000", 16),
    4: int("-0x80000000", 16),
    5: int("-0x8000000000", 16),
    6: int("-0x800000000000", 16),
    7: int("-0x80000000000000", 16),
    8: int("-0x8000000000000000", 16),
    9: int("-0x800000000000000000", 16),
    10: int("-0x80000000000000000000", 16),
    11: int("-0x8000000000000000000000", 16),
    12: int("-0x800000000000000000000000", 16),
    13: int("-0x80000000000000000000000000", 16),
    14: int("-0x8000000000000000000000000000", 16),
    15: int("-0x800000000000000000000000000000", 16),
    16: int("-0x80000000000000000000000000000000", 16),
    17: int("-0x8000000000000000000000000000000000", 16),
    18: int("-0x800000000000000000000000000000000000", 16),
    19: int("-0x80000000000000000000000000000000000000", 16),
    20: int("-0x8000000000000000000000000000000000000000", 16),
    21: int("-0x800000000000000000000000000000000000000000", 16),
    22: int("-0x80000000000000000000000000000000000000000000", 16),
    23: int("-0x8000000000000000000000000000000000000000000000", 16),
    24: int("-0x800000000000000000000000000000000000000000000000", 16),
    25: int("-0x80000000000000000000000000000000000000000000000000", 16),
    26: int("-0x8000000000000000000000000000000000000000000000000000", 16),
    27: int("-0x800000000000000000000000000000000000000000000000000000", 16),
    28: int("-0x80000000000000000000000000000000000000000000000000000000", 16),
    29: int("-0x8000000000000000000000000000000000000000000000000000000000", 16),
    30: int("-0x800000000000000000000000000000000000000000000000000000000000", 16),
    31: int("-0x80000000000000000000000000000000000000000000000000000000000000", 16),
    32: int("-0x8000000000000000000000000000000000000000000000000000000000000000", 16)
}

MAX_RING_BUFFER_LENGTH = 10
MAX_ARRAY_LENGTH = 2

class CircularSet:
    def __init__(self, set_size=MAX_RING_BUFFER_LENGTH, initial_set=None):
        self._q = collections.deque(maxlen=set_size)
        if initial_set:
            self._q.extend(initial_set)

    @property
    def empty(self):
        return len(self._q) == 0

    def add(self, value):
        if value not in self._q:
            self._q.append(value)
        else:
            self._q.remove(value)
            self._q.append(value)

    def head_and_rotate(self):
        value = self._q[-1]
        self._q.rotate(1)
        return value

    def discard(self, value):
        if value in self._q:
            self._q.remove(value)

    def __repr__(self):
        return repr(self._q)


class Generator:
    def __init__(self, interface, bytecode, accounts, token_contract_acount,attack_contract_account,contract,
                # 新增两个参数
                deposit_interface, depositETH_interface,
                tokenHandlerFuncHash, tokens=None,
                falseSignatorys=None,signatoryIndex=None,signatoryType=None,
                paramTypeList= [],valueList = []
                ):
        self.logger = initialize_logger("Generator")
        self.interface = interface
        self.bytecode = bytecode
        self.accounts = accounts
        self.contract = contract

        # add token_contract_acount 
        self.token_contract_acount=token_contract_acount
        self.attack_contract_acount=attack_contract_account

        # Pools
        self.function_circular_buffer = CircularSet(set_size=len(self.interface), initial_set=set(self.interface))
        self.accounts_pool = {}
        self.amounts_pool = {}
        self.arguments_pool = {}
        self.timestamp_pool = {}
        self.blocknumber_pool = {}
        self.balance_pool = {}
        self.callresult_pool = {}
        self.gaslimit_pool = {}
        self.extcodesize_pool = {}
        self.returndatasize_pool = {}
        self.argument_array_sizes_pool = {}
        self.strings_pool = CircularSet()
        self.bytes_pool = CircularSet()


        # 新增deposit_interface 和 depositETH_interface 
        self.deposit_interface = deposit_interface
        self.depositETH_interface = depositETH_interface
        self.deposit_circular_buffer = CircularSet(set_size=len(self.deposit_interface), initial_set=set(self.deposit_interface))



        # 新增token handler 和 token 
        self.tokenHandlerFuncHash = tokenHandlerFuncHash
        self.tokens = tokens

        # 新增记录fake_address  Li.Finance
        self.fake_address=[]


        self.paramTypeList = paramTypeList
        self.valueList = valueList

        # 新增false falseSignatorys 
        self.falseSignatorys = falseSignatorys

        # 新增signatory 的参数位置
        self.signatoryIndex = signatoryIndex


        # 新增signatory 的类型参数
        self.signatoryType = signatoryType




    def generate_random_individual(self):
        individual = []

        if "constructor" in self.interface and self.bytecode:
            arguments = ["constructor"]
            for index in range(len(self.interface["constructor"])):
                arguments.append(self.get_random_argument(self.interface["constructor"][index], "constructor", index))
            individual.append({
                "account": self.get_random_account("constructor"),
                "contract": self.bytecode,
                "amount": self.get_random_amount("constructor"),
                "arguments": arguments,
                "blocknumber": self.get_random_blocknumber("constructor"),
                "timestamp": self.get_random_timestamp("constructor"),
                "gaslimit": self.get_random_gaslimit("constructor"),
                "returndatasize": dict()
            })
        

        function, argument_types = self.get_random_function_with_argument_types()
        print("function = ",function)        
        print("argument_types = ",argument_types)
        arguments = [function]


        # meter
        # arguments.append()

        # multichain
        # address from
        # arguments.append('0x7f4bae93c21b03836d20933ff55d9f77e5b8d34d')
        # # token
        # arguments.append(self.get_random_argument(argument_types[1], function, 1))
        # # arguments.append(self.attack_contract_acount[0])
        # # to
        # arguments.append('0x4986e9017ea60e7afcd10d844f85c80912c3863c')
        # # amount
        # arguments.append(100)
        # # deadline
        # arguments.append(2)
        # # v
        # arguments.append(0)
        # # r
        # arguments.append(self.get_random_argument(argument_types[6], function, 6))
        # # s
        # arguments.append(self.get_random_argument(argument_types[6], function, 6))
        # # toChainID
        # arguments.append(56)          



 
        # 现在只考虑deposit函数
        # todo 改为通过参数配置来选择到底怎么执行


        # # todo 替换成随机数
        # token_index = self.tokens[0]["index"]


        # # function, argument_types = self.get_random_deposit_with_argument_types()
        # function, argument_types = self.get_random_token_handler_func_with_argument_types(self.tokens[0]["function"])
        # arguments = [function]



        # arguments.append(2)  
        # arguments.append(int.to_bytes(int(self.tokens[0]["resourceID"]),byteorder='big',length=32 ))
        # # arguments.append(int.to_bytes(273739586996562601137320895006645807795033755704321,byteorder='big',length=32))
        # # arguments.append(273739586996562601137320895006645807795033755704321)  
        # arguments.append(self.get_random_argument(argument_types[2], function, 2))       


        



        # argument.append()



        # arguments.append(bytearray(bytes.fromhex('0000000000000000000000bb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c01')))
        # arguments.append(self.get_random_argument(argument_types[1], function, 1))
        # arguments.append(bytearray(bytes.fromhex('000000000000000000000000000000000000000000000000000000000000006900000000000000000000000000000000000000000000000a4cc799563c380000000000000000000000000000d01ae1a708614948b2b5e0b7ab5be6afa01325c7')))
        # arguments.append(bytearray(bytes.fromhex('000000000000000000000000000000000000000000000000000000000000006900000000000000000000000000000000000000000000000a4cc799563c380000000000000000000000000000d01ae1a708614948b2b5e0b7ab5be6afa01325c7')))
        # print(argument_types)
        # print(bytearray(bytes.fromhex('0000000000000000000000bb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c01')))


        # todo : 这里不指定byte的参数就会有问题，不知道为什么，待修改 init error 
        for index in range(len(argument_types)):
            flag = False
            for j in range (len(self.paramTypeList)):
                if self.paramTypeList[j] == argument_types[index]:
                    arguments.append(self.valueList[j])
                    flag = True
                    break
            if flag ==False:
                arguments.append(self.get_random_argument(argument_types[index], function, index))      
        # if self.paramTypeList!=None:
        if len(self.paramTypeList) != 0 :
            arguments[3] = bytearray(bytes.fromhex('000000000000000000000000000000000000000000000000000000000000006900000000000000000000000000000000000000000000000a4cc799563c380000000000000000000000000000d01ae1a708614948b2b5e0b7ab5be6afa01325c7'))
        # if self.falseSignatorys == None:
        #     for index in range(len(argument_types)):
        #         # if index==1:
        #         #     arguments.append(0x0000000000000000000000bb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c01)
        #         #     continue
        #         arguments.append(self.get_random_argument(argument_types[index], function, index))
        # else: 
        #     for index in range(len(argument_types)):
        #         print(type(self.signatoryIndex))
        #         if index == int(self.signatoryIndex)+1:
        #             falseSignatorys = self.getSignatorys(self.falseSignatorys[0])
        #             arguments.append(falseSignatorys)   
        #         else:
        #             arguments.append(self.get_random_argument(argument_types[index], function, index))        
        
        print("argument = ",arguments)
        individual.append({
            "account": self.get_random_account(function),
            "contract": self.contract,
            "amount": self.get_random_amount(function),
            "arguments": arguments,
            "blocknumber": self.get_random_blocknumber(function),
            "timestamp": self.get_random_timestamp(function),
            "gaslimit": self.get_random_gaslimit(function),
            "call_return": dict(),
            "extcodesize": dict(),
            "returndatasize": dict()
        })

        address, call_return_value = self.get_random_callresult_and_address(function)
        individual[-1]["call_return"] = {address: call_return_value}

        address, extcodesize_value = self.get_random_extcodesize_and_address(function)
        individual[-1]["extcodesize"] = {address: extcodesize_value}

        address, value = self.get_random_returndatasize_and_address(function)
        individual[-1]["returndatasize"] = {address: value}

        return individual

    def generate_random_input(self):
        input = {}

        function, argument_types = self.get_random_function_with_argument_types()
        arguments = [function]
        for index in range(len(argument_types)):
            arguments.append(self.get_random_argument(argument_types[index], function, index))
        input = {
            "account": self.get_random_account(function),
            "contract": self.contract,
            "amount": self.get_random_amount(function),
            "arguments": arguments,
            "blocknumber": self.get_random_blocknumber(function),
            "timestamp": self.get_random_timestamp(function),
            "gaslimit": self.get_random_gaslimit(function),
            "returndatasize": dict()
        }

        address, value = self.get_random_returndatasize_and_address(function)
        input["returndatasize"] = {address: value}

        return input

    def get_random_function_with_argument_types(self):
        # # 这里先写死，function_hash
        function_hash = self.function_circular_buffer.head_and_rotate()

        if function_hash == "constructor":
            function_hash = self.function_circular_buffer.head_and_rotate()
        # print("function_hash = ",function_hash)
        # print("interface  = ",self.interface[function_hash])        
        
        
        # mulitichain 的function hash 
        # function_hash='0x8d7d3eea'

        # meter.io function hash
        # function_hash = "0x05e2ca17"
        # return function_hash, self.interface[function_hash]
        # function_hash='0x8d7d3eea'
        # print("function_hash = ",function_hash)
        # print("interface  = ",self.interface[function_hash])  


        # Li.Finance 的function hash '0xc2c134df'
        # function_hash = '0x01c0a31a'

        # # chainswap
        # function_hash = '0xa653d60c'


        # Qbridge
        # function_hash = '0xb07e54bb'



        # function_hash = self.function_circular_buffer.head_and_rotate()

        return function_hash , self.interface[function_hash]

    # 新增deposit 的 function hash选择
    def get_random_deposit_with_argument_types(self):
        function_hash = self.deposit_circular_buffer.head_and_rotate()
        return function_hash , self.deposit_interface[function_hash]


    def get_random_token_handler_func_with_argument_types(self,tokenFunc):
        # 遍历字典
        # todo 加入随机元素选择
        canCallFunction = [] 
        for key in self.tokenHandlerFuncHash:
            if key != tokenFunc:
                canCallFunction.append(self.tokenHandlerFuncHash[key])
        # print(type(canCallFunction[0].keys()))
        function_hash = list(canCallFunction[0].keys())[0]
        function_interface =  self.interface[function_hash]
        return function_hash, function_interface 


    #
    # TIMESTAMP
    #

    def add_timestamp_to_pool(self, function, timestamp):
        if not function in self.timestamp_pool:
            self.timestamp_pool[function] = CircularSet()
        self.timestamp_pool[function].add(timestamp)

    def get_random_timestamp(self, function):
        if function in self.timestamp_pool:
            return self.timestamp_pool[function].head_and_rotate()
        return None

    def remove_timestamp_from_pool(self, function, timestamp):
        if function in self.timestamp_pool:
            self.timestamp_pool[function].discard(timestamp)
            if self.timestamp_pool[function].empty:
                del self.timestamp_pool[function]

    #
    # BLOCKNUMBER
    #

    def add_blocknumber_to_pool(self, function, blocknumber):
        if not function in self.blocknumber_pool:
            self.blocknumber_pool[function] = CircularSet()
        self.blocknumber_pool[function].add(blocknumber)

    def get_random_blocknumber(self, function):
        if function in self.blocknumber_pool:
            return self.blocknumber_pool[function].head_and_rotate()
        return None

    def remove_blocknumber_from_pool(self, function, blocknumber):
        if function in self.blocknumber_pool:
            self.blocknumber_pool[function].discard(blocknumber)
            if self.blocknumber_pool[function].empty:
                del self.blocknumber_pool[function]

    #
    # BALANCE
    #

    def add_balance_to_pool(self, function, balance):
        if not function in self.balance_pool:
            self.balance_pool[function] = CircularSet()
        self.balance_pool[function].add(balance)

    def get_random_balance(self, function):
        if function in self.balance_pool:
            return self.balance_pool[function].head_and_rotate()
        return None

    #
    # CALL RESULT
    #

    def add_callresult_to_pool(self, function, address, result):
        if not function in self.callresult_pool:
            self.callresult_pool[function] = dict()
        if not address in self.callresult_pool[function]:
            self.callresult_pool[function][address] = CircularSet()
        self.callresult_pool[function][address].add(result)

    def get_random_callresult_and_address(self, function):
        if function in self.callresult_pool:
            address = random.choice(list(self.callresult_pool[function].keys()))
            value = self.callresult_pool[function][address].head_and_rotate()
            return address, value
        return None, None

    def get_random_callresult(self, function, address):
        if function in self.callresult_pool:
            if address in self.callresult_pool[function]:
                value = self.callresult_pool[function][address].head_and_rotate()
                return value
        return None

    def remove_callresult_from_pool(self, function, address, result):
        if function in self.callresult_pool and address in self.callresult_pool[function]:
            self.callresult_pool[function][address].discard(result)
            if self.callresult_pool[function][address].empty:
                del self.callresult_pool[function][address]
                if len(self.callresult_pool[function]) == 0:
                    del self.callresult_pool[function]

    #
    # EXTCODESIZE
    #

    def add_extcodesize_to_pool(self, function, address, size):
        if not function in self.extcodesize_pool:
            self.extcodesize_pool[function] = dict()
        if not address in self.extcodesize_pool[function]:
            self.extcodesize_pool[function][address] = CircularSet()
        self.extcodesize_pool[function][address].add(size)

    def get_random_extcodesize_and_address(self, function):
        if function in self.extcodesize_pool:
            address = random.choice(list(self.extcodesize_pool[function].keys()))
            return address, self.extcodesize_pool[function][address].head_and_rotate()
        return None, None

    def get_random_extcodesize(self, function, address):
        if function in self.extcodesize_pool:
            if address in self.extcodesize_pool[function]:
                return self.extcodesize_pool[function][address].head_and_rotate()
        return None

    def remove_extcodesize_from_pool(self, function, address, size):
        if function in self.extcodesize_pool and address in self.extcodesize_pool[function]:
            self.extcodesize_pool[function][address].discard(size)
            if self.extcodesize_pool[function][address].empty:
                del self.extcodesize_pool[function][address]
                if len(self.extcodesize_pool[function]) == 0:
                    del self.extcodesize_pool[function]

    #
    # RETURNDATASIZE
    #

    def add_returndatasize_to_pool(self, function, address, size):
        if not function in self.returndatasize_pool:
            self.returndatasize_pool[function] = dict()
        if not address in self.returndatasize_pool[function]:
            self.returndatasize_pool[function][address] = CircularSet()
        self.returndatasize_pool[function][address].add(size)

    def get_random_returndatasize_and_address(self, function):
        if function in self.returndatasize_pool:
            address = random.choice(list(self.returndatasize_pool[function].keys()))
            return address, self.returndatasize_pool[function][address].head_and_rotate()
        return None, None

    def get_random_returndatasize(self, function, address):
        if function in self.returndatasize_pool:
            if address in self.returndatasize_pool[function]:
                return self.returndatasize_pool[function][address].head_and_rotate()
        return None

    def remove_returndatasize_from_pool(self, function, address, size):
        if function in self.returndatasize_pool and address in self.returndatasize_pool[function]:
            self.returndatasize_pool[function][address].discard(size)
            if self.returndatasize_pool[function][address].empty:
                del self.returndatasize_pool[function][address]
                if len(self.returndatasize_pool[function]) == 0:
                    del self.returndatasize_pool[function]

    #
    # GASLIMIT
    #

    def add_gaslimit_to_pool(self, function, gaslimit):
        if not function in self.gaslimit_pool:
            self.gaslimit_pool[function] = CircularSet()
        self.gaslimit_pool[function].add(gaslimit)

    def remove_gaslimit_from_pool(self, function, gaslimit):
        if function in self.gaslimit_pool:
            self.gaslimit_pool[function].discard(gaslimit)
            if self.gaslimit_pool[function].empty:
                del self.gaslimit_pool[function]

    def clear_gaslimits_in_pool(self, function):
        if function in self.gaslimit_pool:
            del self.gaslimit_pool[function]

    def get_random_gaslimit(self, function):
        if function in self.gaslimit_pool:
            return self.gaslimit_pool[function].head_and_rotate()
        return settings.GAS_LIMIT

    #
    # ACCOUNTS
    #

    def add_account_to_pool(self, function, account):
        if not function in self.accounts_pool:
            self.accounts_pool[function] = CircularSet()
        self.accounts_pool[function].add(account)

    def remove_account_from_pool(self, function, account):
        if function in self.accounts_pool:
            self.accounts_pool[function].discard(account)
            if self.accounts_pool[function].empty:
                del self.accounts_pool[function]

    def clear_accounts_in_pool(self, function):
        if function in self.accounts_pool:
            self.accounts_pool[function] = CircularSet()

    def get_random_account_from_pool(self, function):
        return self.accounts_pool[function].head_and_rotate()

    def get_random_account(self, function):
        if function in self.accounts_pool:
            return self.get_random_account_from_pool(function)
        else:
            return random.choice(self.accounts)

    #
    # AMOUNTS
    #

    def add_amount_to_pool(self, function, amount):
        if not function in self.amounts_pool:
            self.amounts_pool[function] = CircularSet()
        self.amounts_pool[function].add(amount)

    def remove_amount_from_pool(self, function, amount):
        if function in self.amounts_pool:
            self.amounts_pool[function].discard(amount)
            if self.amounts_pool[function].empty:
                del self.amounts_pool[function]

    def get_random_amount_from_pool(self, function):
        return self.amounts_pool[function].head_and_rotate()

    def get_random_amount(self, function):
        if function in self.amounts_pool:
            amount = self.get_random_amount_from_pool(function)
        else:
            amount = random.randint(0, 1)
            self.add_amount_to_pool(function, amount)
            self.add_amount_to_pool(function, 1 - amount)
        return amount

    #
    # STRINGS
    #

    def add_string_to_pool(self, string):
        self.strings_pool.add(string)


    def get_random_string_from_pool(self):
        return self.strings_pool.head_and_rotate()

    #
    # BYTES
    #

    def add_bytes_to_pool(self, string):
        self.bytes_pool.add(string)


    def get_random_bytes_from_pool(self):
        return self.bytes_pool.head_and_rotate()

    #
    # FUNCTION ARGUMENTS
    #

    def add_parameter_array_size(self, function, parameter_index, array_size):
        if function not in self.argument_array_sizes_pool:
            self.argument_array_sizes_pool[function] = dict()
        if parameter_index not in self.argument_array_sizes_pool[function]:
            self.argument_array_sizes_pool[function][parameter_index] = CircularSet()
        self.argument_array_sizes_pool[function][parameter_index].add(min(array_size, MAX_ARRAY_LENGTH))

    def _get_parameter_array_size_from_pool(self, function, argument_index):
        return self.argument_array_sizes_pool[function][argument_index].head_and_rotate()

    def remove_parameter_array_size_from_pool(self, function, parameter_index, array_size):
        if function in self.argument_array_sizes_pool and parameter_index in self.argument_array_sizes_pool[function]:
            self.argument_array_sizes_pool[function][parameter_index].discard(array_size)
            if self.argument_array_sizes_pool[function][parameter_index].empty:
                del self.argument_array_sizes_pool[function][parameter_index]
                if len(self.argument_array_sizes_pool[function]) == 0:
                    del self.argument_array_sizes_pool[function]


    def add_argument_to_pool(self, function, argument_index, argument):
        if type(argument) is list:
            for element in argument:
                self.add_argument_to_pool(function, argument_index, element)
            return
        if function not in self.arguments_pool:
            self.arguments_pool[function] = {}
        if argument_index not in self.arguments_pool[function]:
            self.arguments_pool[function][argument_index] = CircularSet()
        self.arguments_pool[function][argument_index].add(argument)

    def remove_argument_from_pool(self, function, argument_index, argument):
        if type(argument) is list:
            for element in argument:
                self.remove_argument_from_pool(function, argument_index, element)
            return
        if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
            self.arguments_pool[function][argument_index].discard(argument)
            if self.arguments_pool[function][argument_index].empty:
                del self.arguments_pool[function][argument_index]
                if len(self.arguments_pool[function]) == 0:
                    del self.arguments_pool[function]

    def _get_random_argument_from_pool(self, function, argument_index):
        return self.arguments_pool[function][argument_index].head_and_rotate()

    def get_random_argument(self, type, function, argument_index):
        # 这里需要新增数据tuple的生成
        # Boolean
        if type.startswith("bool"):
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        if self._get_random_argument_from_pool(function, argument_index) == 0:
                            array.append(False)
                        else:
                            array.append(True)
                    else:
                        if random.randint(0, 1) == 0:
                            array.append(False)
                        else:
                            array.append(True)
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    if self._get_random_argument_from_pool(function, argument_index) == 0:
                        return False
                    return True
                else:
                    if random.randint(0, 1) == 0:
                        return False
                    return True

        # Unsigned integer
        elif type.startswith("uint"):
            bytes = int(int(type.replace("uint", "").split("[")[0]) / 8)
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        array.append(self._get_random_argument_from_pool(function, argument_index))
                    else:
                        array.append(self.get_random_unsigned_integer(0, UINT_MAX[bytes]))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                return self.get_random_unsigned_integer(0, UINT_MAX[bytes])

        # Signed integer
        elif type.startswith("int"):
            bytes = int(int(type.replace("int", "").split("[")[0]) / 8)
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        array.append(self._get_random_argument_from_pool(function, argument_index))
                    else:
                        array.append(self.get_random_signed_integer(INT_MIN[bytes], INT_MAX[bytes]))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                return self.get_random_signed_integer(INT_MIN[bytes], INT_MAX[bytes])

        # Address
        elif type.startswith("address"):
            # Array
            if "[" in type and "]" in type:
            # 这里先写死
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        array.append(self._get_random_argument_from_pool(function, argument_index))
                    else:
                        array.append(random.choice(self.accounts))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array

            
            # Single value
            # Todo 一种是选择攻击账号，另一种是使用token的 address 池
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    address = self._get_random_argument_from_pool(function, argument_index)
                # # 可以从attack 中选择地址
                elif len(self.attack_contract_acount)!=0:
                    #print("token_contract_account= ",self.token_contract_acount)
                    # print(random.choice(self.token_contract_acount))
                    # print(random.choice(self.attack_contract_acount))
                    address = random.choice(self.attack_contract_acount)
                else:
                    address = random.choice(self.accounts)
                
                if address not in self.fake_address: 
                    self.fake_address.append(address)
                return address

        # String
        elif type.startswith("string"):
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    array.append(self.get_string(random.randint(0, MAX_ARRAY_LENGTH)))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                if self.strings_pool.empty:
                    self.add_string_to_pool(self.get_string(0))
                    self.add_string_to_pool(self.get_string(1))
                    self.add_string_to_pool(self.get_string(32))
                    self.add_string_to_pool(self.get_string(33))
                return self.get_random_string_from_pool()

        # Bytes1 ... Bytes32
        elif type.startswith("bytes1") or \
             type.startswith("bytes2") or \
             type.startswith("bytes3") or \
             type.startswith("bytes4") or \
             type.startswith("bytes5") or \
             type.startswith("bytes6") or \
             type.startswith("bytes7") or \
             type.startswith("bytes8") or \
             type.startswith("bytes9") or \
             type.startswith("bytes10") or \
             type.startswith("bytes11") or \
             type.startswith("bytes12") or \
             type.startswith("bytes13") or \
             type.startswith("bytes14") or \
             type.startswith("bytes15") or \
             type.startswith("bytes16") or \
             type.startswith("bytes17") or \
             type.startswith("bytes18") or \
             type.startswith("bytes19") or \
             type.startswith("bytes20") or \
             type.startswith("bytes21") or \
             type.startswith("bytes22") or \
             type.startswith("bytes23") or \
             type.startswith("bytes24") or \
             type.startswith("bytes25") or \
             type.startswith("bytes26") or \
             type.startswith("bytes27") or \
             type.startswith("bytes28") or \
             type.startswith("bytes29") or \
             type.startswith("bytes30") or \
             type.startswith("bytes31") or \
             type.startswith("bytes32"):
            length = int(type.replace("bytes", "").split("[")[0])
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        array.append(self._get_random_argument_from_pool(function, argument_index))
                    else:
                        array.append(self.get_random_bytes(length))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                return self.get_random_bytes(random.randint(0, length))

        # Bytes
        elif type.startswith("bytes"):
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    array.append(self.get_random_bytes(random.randint(0, MAX_ARRAY_LENGTH)))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                if self.bytes_pool.empty:
                    self.add_bytes_to_pool(self.get_random_bytes(0))
                    self.add_bytes_to_pool(self.get_random_bytes(1))
                    self.add_bytes_to_pool(self.get_random_bytes(32))
                    self.add_bytes_to_pool(self.get_random_bytes(33))
                return self.get_random_bytes_from_pool()
        
        elif type.startswith("("):
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                # tuple应该不等于0
                sizes[0]+=1
                for _ in range(sizes[0]):
                    array.append(self.get_random_tuple(type[1:-3],function, argument_index))
                    return array
            # Single value
            else:
                # if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                #     return self._get_random_argument_from_pool(function, argument_index)
                ## tuple{xxx,xxxx}
                return self.get_random_tuple(type[1:-1],function, argument_index)

        # Unknown type
        else:
            self.logger.error("Unsupported type: "+str(type))


    def get_random_tuple(self,internalTypes,function, argument_index):
        internalTypeArr=internalTypes.split(',')
        tuple_val=[]
        for internalType in internalTypeArr:
            tuple_val.append(self.get_random_argument(internalType, function, argument_index))
        return tuple(tuple_val)

    def _get_array_sizes(self, argument_index, function, type):
        sizes = []
        for size in re.compile(r"\[(.*?)\]").findall(type):
            # Dynamic array
            if size == "":
                if function in self.argument_array_sizes_pool \
                        and argument_index in self.argument_array_sizes_pool[function]:
                    sizes.append(self._get_parameter_array_size_from_pool(function, argument_index))
                else:
                    sizes.append(random.randint(0, MAX_ARRAY_LENGTH))
            # Fixed size array
            else:
                sizes.append(int(size))
        return sizes


    def getSignatorys(self,signatory):
        signatoryType = self.signatoryType["type"]

        if signatoryType == 'tuple[]':
            signatoryArr = []
            tuple_val=[]
            # print(type(self.signatoryType))
            for key,item in self.signatoryType.items():
                if key == 'type':
                    continue
                # print(signatory[key])

                value = self.covertValue(item,signatory[key])
                tuple_val.append(value)
            # print(tuple_val)
            # print(signatory)
            # print(tuple(tuple_val))
            signatoryArr.append(tuple(tuple_val))
            # print(signatoryArr)
            return signatoryArr
        #print("------")

    def covertValue(self,type,value):
        if type.startswith("address"):
            return value
        elif type.startswith("uint"):
            return int(value)
        elif type.startswith("bytes1") or \
             type.startswith("bytes2") or \
             type.startswith("bytes3") or \
             type.startswith("bytes4") or \
             type.startswith("bytes5") or \
             type.startswith("bytes6") or \
             type.startswith("bytes7") or \
             type.startswith("bytes8") or \
             type.startswith("bytes9") or \
             type.startswith("bytes10") or \
             type.startswith("bytes11") or \
             type.startswith("bytes12") or \
             type.startswith("bytes13") or \
             type.startswith("bytes14") or \
             type.startswith("bytes15") or \
             type.startswith("bytes16") or \
             type.startswith("bytes17") or \
             type.startswith("bytes18") or \
             type.startswith("bytes19") or \
             type.startswith("bytes20") or \
             type.startswith("bytes21") or \
             type.startswith("bytes22") or \
             type.startswith("bytes23") or \
             type.startswith("bytes24") or \
             type.startswith("bytes25") or \
             type.startswith("bytes26") or \
             type.startswith("bytes27") or \
             type.startswith("bytes28") or \
             type.startswith("bytes29") or \
             type.startswith("bytes30") or \
             type.startswith("bytes31") or \
             type.startswith("bytes32"):
            length = int(type.replace("bytes", "").split("[")[0])
            return bytearray(bytes.fromhex(value[2:]))
                    
        






    @staticmethod
    def get_random_unsigned_integer(min, max):
        seed = int(random.uniform(-2, 2))
        if seed == -1:
            return random.choice([min, min + 1, min + 2])
        elif seed == 1:
            return random.choice([max, max - 1, max - 2])
        else:
            return random.randint(min, max)

    @staticmethod
    def get_random_signed_integer(min, max):
        seed = int(random.uniform(-2, 2))
        if seed == -1:
            return random.choice([0, -1, min, min + 1])
        elif seed == 1:
            return random.choice([0, 1, max, max - 1])
        else:
            return random.randint(min, max)

    @staticmethod
    def get_string(length):
        return ''.join('A' for _ in range(length))

    @staticmethod
    def get_random_bytes(length):
        return bytearray(random.getrandbits(8) for _ in range(length))





        


