#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from z3 import is_expr
from z3.z3util import get_vars
from utils.utils import convert_stack_value_to_int

class UncheckAddressParameterDetector():
    def __init__(self):
        self.init()

    def init(self):
        self.swc_id = 104
        self.severity = "Low"
        self.exceptions = {}
        self.external_function_calls = {}
        #self.contract=""

    # todo 增加token的判断
    def detect_uncheck_address_parameter(self, tainted_record, current_instruction, transaction_index,fake_address):
        # if current_instruction["op"] in ["CALL"]:
        #     print(str(hex(convert_stack_value_to_int(current_instruction["stack"][-2]))))
        #     print(hex(convert_stack_value_to_int(current_instruction["stack"][-2])) in fake_address)
        if current_instruction["op"] in ["CALL"] and hex(convert_stack_value_to_int(current_instruction["stack"][-2])) in fake_address and convert_stack_value_to_int(current_instruction["stack"][-5]) > 0:
            self.external_function_calls[convert_stack_value_to_int(current_instruction["stack"][-6])] = current_instruction["pc"], transaction_index

        if current_instruction["op"] in ["RETURN", "STOP", "SUICIDE", "SELFDESTRUCT"] : 
            for external_function_call in self.external_function_calls:
                return self.external_function_calls[external_function_call]
        return None, None

