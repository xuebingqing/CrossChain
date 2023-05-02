#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from z3 import is_expr
from z3.z3util import get_vars
from utils.utils import convert_stack_value_to_int

class SignatureVerificationMissingDetector():
    def __init__(self):
        self.init()

    def init(self):
        self.swc_id = 1011
        self.severity = "Low"
        self.exceptions = {}
        self.external_function_calls = {}
        self.signatory_check = False
        #self.contract=""

    # todo 增加token的判断
    def detect_signature_verification_missing(self, tainted_record, current_instruction, transaction_index):

        if current_instruction["op"] in ["RETURN", "STOP", "SUICIDE", "SELFDESTRUCT"] and self.signatory_check: 
            return 111,111
        return None , None

