#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from z3 import is_expr
from z3.z3util import get_vars
from utils.utils import convert_stack_value_to_int

class InitErrorDetector():
    def __init__(self):
        self.init()

    def init(self):
        self.swc_id = 107
        self.severity = "High"
        self.exceptions = {}
        self.external_function_calls = {}

    def detect_init_error(self, current_instruction, tainted_record, transaction_index, contract_dict, source_map):
        # Register all exceptions
        if current_instruction and current_instruction["op"] in ["CALL", "CALLCODE", "DELEGATECALL", "STATICCALL"]:
            # print(convert_stack_value_to_int(current_instruction["stack"][-2]))
            if convert_stack_value_to_int(current_instruction["stack"][-2]) == 0: 
                self.external_function_calls[convert_stack_value_to_int(current_instruction["stack"][-6])] = current_instruction["pc"], transaction_index

        if current_instruction["op"] in ["RETURN", "STOP", "SUICIDE", "SELFDESTRUCT"] : 
            for external_function_call in self.external_function_calls:
                return self.external_function_calls[external_function_call]
        return None, None
