#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time

from utils.utils import print_individual_solution_as_transaction, initialize_logger

from .integer_overflow import IntegerOverflowDetector
from .assertion_failure import AssertionFailureDetector
from .arbitrary_memory_access import ArbitraryMemoryAccessDetector
from .reentrancy import ReentrancyDetector
from .transaction_order_dependency import TransactionOrderDependencyDetector
from .block_dependency import BlockDependencyDetector
from .unchecked_return_value import UncheckedReturnValueDetector
from .unsafe_delegatecall import UnsafeDelegatecallDetector
from .leaking_ether import LeakingEtherDetector
from .locking_ether import LockingEtherDetector
from .unprotected_selfdestruct import UnprotectedSelfdestructDetector
from .interface_compatibility import InterfaceCompatibilityDetector
from .uncheck_token_type import UncheckTokenTypeDetector
from .uncheck_address_parameter import UncheckAddressParameterDetector
from .signature_verification_missing import SignatureVerificationMissingDetector
from .init_error import InitErrorDetector




class DetectorExecutor:
    def __init__(self, source_map=None, attack_contract_source_map=None,token_contract_source_map=None,token_interface_name=[],function_signature_mapping={}):
        self.source_map = source_map

        ## 新增token的所有ABI
        self.contract_dict={}

        self.fake_address=[]

        # 新增generator
        self.generator = None

        self.function_signature_mapping = function_signature_mapping
        self.logger = initialize_logger("Detector")

        self.integer_overflow_detector = IntegerOverflowDetector()
        self.assertion_failure_detector = AssertionFailureDetector()
        self.arbitrary_memory_access_detector = ArbitraryMemoryAccessDetector()
        self.reentrancy_detector = ReentrancyDetector()
        self.transaction_order_dependency_detector = TransactionOrderDependencyDetector()
        self.block_dependency_detector = BlockDependencyDetector()
        self.unchecked_return_value_detector = UncheckedReturnValueDetector()
        self.unsafe_delegatecall_detector = UnsafeDelegatecallDetector()
        self.leaking_ether_detector = LeakingEtherDetector()
        self.locking_ether_detector = LockingEtherDetector()
        self.unprotected_selfdestruct_detector = UnprotectedSelfdestructDetector()
        self.interface_compatibility = InterfaceCompatibilityDetector()
        self.uncheck_token_type = UncheckTokenTypeDetector()
        self.uncheck_address_parameter = UncheckAddressParameterDetector()
        self.signature_verification_missing = SignatureVerificationMissingDetector()
        self.init_error = InitErrorDetector()


    def initialize_detectors(self):
        self.integer_overflow_detector.init()
        self.assertion_failure_detector.init()
        self.arbitrary_memory_access_detector.init()
        self.reentrancy_detector.init()
        self.transaction_order_dependency_detector.init()
        self.block_dependency_detector.init()
        self.unchecked_return_value_detector.init()
        self.unsafe_delegatecall_detector.init()
        self.leaking_ether_detector.init()
        self.locking_ether_detector.init()
        self.unprotected_selfdestruct_detector.init()
        self.init_error.init()

    @staticmethod
    def error_exists(errors, type):
        for error in errors:
            if error["type"] == type:
                return True
        return False

    @staticmethod
    def add_error(errors, pc, type, individual, mfe, detector, source_map):
        error = {
            "swc_id": detector.swc_id,
            "severity": detector.severity,
            "type": type,
            "individual": individual.solution,
            "time": time.time() - mfe.execution_begin,

        }
        if source_map and source_map.get_buggy_line(pc):
            error["line"] = source_map.get_location(pc)['begin']['line'] + 1
            error["column"] = source_map.get_location(pc)['begin']['column'] + 1
            error["source_code"] = source_map.get_buggy_line(pc)
        if not pc in errors:
            errors[pc] = [error]
            return True
        elif not DetectorExecutor.error_exists(errors[pc], type):
            errors[pc].append(error)
            return True
        return False

    def get_color_for_severity(severity):
        if severity == "High":
            return "\u001b[31m" # Red
        if severity == "Medium":
            return "\u001b[33m" # Yellow
        if severity == "Low":
            return "\u001b[32m" # Green
        return ""

    def run_detectors(self, previous_instruction, current_instruction, errors, tainted_record, individual, mfe, previous_branch, transaction_index):
        pc, index = self.arbitrary_memory_access_detector.detect_arbitrary_memory_access(tainted_record, individual, current_instruction, transaction_index)
        if pc and DetectorExecutor.add_error(errors, pc, "Arbitrary Memory Access", individual, mfe, self.arbitrary_memory_access_detector, self.source_map):
            color = DetectorExecutor.get_color_for_severity(self.arbitrary_memory_access_detector.severity)
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"      !!! Arbitrary memory access detected !!!       ")
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"SWC-ID:   "+str(self.arbitrary_memory_access_detector.swc_id))
            self.logger.title(color+"Severity: "+self.arbitrary_memory_access_detector.severity)
            self.logger.title(color+"-----------------------------------------------------")
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+"Source code line:")
                self.logger.title(color+"-----------------------------------------------------")
                line = self.source_map.get_location(pc)['begin']['line'] + 1
                column = self.source_map.get_location(pc)['begin']['column'] + 1
                self.logger.title(color+self.source_map.source.filename+":"+str(line)+":"+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))
                self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"Transaction sequence:")
            self.logger.title(color+"-----------------------------------------------------")
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)

        pc, index = self.assertion_failure_detector.detect_assertion_failure(current_instruction, transaction_index)
        if pc and DetectorExecutor.add_error(errors, pc, "Assertion Failure", individual, mfe, self.assertion_failure_detector, self.source_map):
            color = DetectorExecutor.get_color_for_severity(self.assertion_failure_detector.severity)
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"          !!! Assertion failure detected !!!         ")
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"SWC-ID:   "+str(self.assertion_failure_detector.swc_id))
            self.logger.title(color+"Severity: "+self.assertion_failure_detector.severity)
            self.logger.title(color+"-----------------------------------------------------")
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+"Source code line:")
                self.logger.title(color+"-----------------------------------------------------")
                line = self.source_map.get_location(pc)['begin']['line'] + 1
                column = self.source_map.get_location(pc)['begin']['column'] + 1
                self.logger.title(color+self.source_map.source.filename+":"+str(line)+":"+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))
                self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"Transaction sequence:")
            self.logger.title(color+"-----------------------------------------------------")
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)

        pc, index, type = self.integer_overflow_detector.detect_integer_overflow(mfe, tainted_record, previous_instruction, current_instruction, individual, transaction_index)
        if pc and DetectorExecutor.add_error(errors, pc, "Integer Overflow", individual, mfe, self.integer_overflow_detector, self.source_map):
            color = DetectorExecutor.get_color_for_severity(self.integer_overflow_detector.severity)
            if type == "overflow":
                self.logger.title(color+"-----------------------------------------------------")
                self.logger.title(color+"          !!! Integer overflow detected !!!          ")
                self.logger.title(color+"-----------------------------------------------------")
            else:
                self.logger.title(color+"-----------------------------------------------------")
                self.logger.title(color+"          !!! Integer underflow detected !!!          ")
                self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"SWC-ID:   "+str(self.integer_overflow_detector.swc_id))
            self.logger.title(color+"Severity: "+self.integer_overflow_detector.severity)
            self.logger.title(color+"-----------------------------------------------------")
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+"Source code line:")
                self.logger.title(color+"-----------------------------------------------------")
                line = self.source_map.get_location(pc)['begin']['line'] + 1
                column = self.source_map.get_location(pc)['begin']['column'] + 1
                self.logger.title(color+self.source_map.source.filename+":"+str(line)+":"+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))
                self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"Transaction sequence:")
            self.logger.title(color+"-----------------------------------------------------")
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)

        pc, index = self.reentrancy_detector.detect_reentrancy(tainted_record, current_instruction, transaction_index)
        if pc and DetectorExecutor.add_error(errors, pc, "Reentrancy", individual, mfe, self.reentrancy_detector, self.source_map):
            color = DetectorExecutor.get_color_for_severity(self.reentrancy_detector.severity)
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"            !!! Reentrancy detected !!!              ")
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"SWC-ID:   "+str(self.reentrancy_detector.swc_id))
            self.logger.title(color+"Severity: "+self.reentrancy_detector.severity)
            self.logger.title(color+"-----------------------------------------------------")
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+"Source code line:")
                self.logger.title(color+"-----------------------------------------------------")
                line = self.source_map.get_location(pc)['begin']['line'] + 1
                column = self.source_map.get_location(pc)['begin']['column'] + 1
                self.logger.title(color+self.source_map.source.filename+":"+str(line)+":"+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))
                self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"Transaction sequence:")
            self.logger.title(color+"-----------------------------------------------------")
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)

        pc, index = self.transaction_order_dependency_detector.detect_transaction_order_dependency(current_instruction, tainted_record, individual, transaction_index)
        if pc and DetectorExecutor.add_error(errors, pc, "Transaction Order Dependency", individual, mfe, self.transaction_order_dependency_detector, self.source_map):
            color = DetectorExecutor.get_color_for_severity(self.transaction_order_dependency_detector.severity)
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"    !!! Transaction order dependency detected !!!    ")
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"SWC-ID:   "+str(self.transaction_order_dependency_detector.swc_id))
            self.logger.title(color+"Severity: "+self.transaction_order_dependency_detector.severity)
            self.logger.title(color+"-----------------------------------------------------")
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+"Source code line:")
                self.logger.title(color+"-----------------------------------------------------")
                line = self.source_map.get_location(pc)['begin']['line'] + 1
                column = self.source_map.get_location(pc)['begin']['column'] + 1
                self.logger.title(color+self.source_map.source.filename+":"+str(line)+":"+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))
                self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"Transaction sequence:")
            self.logger.title(color+"-----------------------------------------------------")
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)

        pc, index = self.block_dependency_detector.detect_block_dependency(tainted_record, current_instruction, previous_branch, transaction_index)
        if pc and DetectorExecutor.add_error(errors, pc, "Block Dependency", individual, mfe, self.block_dependency_detector, self.source_map):
            color = DetectorExecutor.get_color_for_severity(self.block_dependency_detector.severity)
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"          !!! Block dependency detected !!!          ")
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"SWC-ID:   "+str(self.block_dependency_detector.swc_id))
            self.logger.title(color+"Severity: "+self.block_dependency_detector.severity)
            self.logger.title(color+"-----------------------------------------------------")
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+"Source code line:")
                self.logger.title(color+"-----------------------------------------------------")
                line = self.source_map.get_location(pc)['begin']['line'] + 1
                column = self.source_map.get_location(pc)['begin']['column'] + 1
                self.logger.title(color+self.source_map.source.filename+":"+str(line)+":"+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))
                self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"Transaction sequence:")
            self.logger.title(color+"-----------------------------------------------------")
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)

        # pc, index = self.unchecked_return_value_detector.detect_unchecked_return_value(previous_instruction, current_instruction, tainted_record, transaction_index,self.contract_dict)
        # if pc and DetectorExecutor.add_error(errors, pc, "Unchecked Return Value", individual, mfe, self.unchecked_return_value_detector, self.source_map):
        #     color = DetectorExecutor.get_color_for_severity(self.unchecked_return_value_detector.severity)
        #     self.logger.title(color+"-----------------------------------------------------")
        #     self.logger.title(color+"        !!! Unchecked return value detected !!!         ")
        #     self.logger.title(color+"-----------------------------------------------------")
        #     self.logger.title(color+"SWC-ID:   "+str(self.unchecked_return_value_detector.swc_id))
        #     self.logger.title(color+"Severity: "+self.unchecked_return_value_detector.severity)
        #     self.logger.title(color+"-----------------------------------------------------")
        #     if self.source_map and self.source_map.get_buggy_line(pc):
        #         self.logger.title(color+"Source code line:")
        #         self.logger.title(color+"-----------------------------------------------------")
        #         line = self.source_map.get_location(pc)['begin']['line'] + 1
        #         column = self.source_map.get_location(pc)['begin']['column'] + 1
        #         self.logger.title(color+self.source_map.source.filename+":"+str(line)+":"+str(column))
        #         self.logger.title(color+self.source_map.get_buggy_line(pc))

        #         # 这里选择function 
        #         callerfunction=self.source_map.get_buggy_line(pc)
        #         spotSite=callerfunction.find(".")
                
        #         # todo spotSite位置的判断

        #         kuohaoSite=callerfunction.find("(",spotSite)
        #         calledfunction=callerfunction[spotSite+1:kuohaoSite]

        #         self.logger.title(color+"-----------------------------------------------------")
        #     self.logger.title(color+"Transaction sequence:")
        #     self.logger.title(color+"-----------------------------------------------------")
        #     print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)


        # 这里存在一些问题，比如token 的ABI不在这里面
        # pc, index = self.interface_compatibility.detect_interface_compatibility(previous_instruction, current_instruction, tainted_record, transaction_index,self.contract_dict,self.source_map)
        # if pc and DetectorExecutor.add_error(errors, pc, "Interface compatibility", individual, mfe, self.unchecked_return_value_detector, self.source_map):
        #     color = DetectorExecutor.get_color_for_severity(self.unchecked_return_value_detector.severity)
        #     self.logger.title(color+"-----------------------------------------------------")
        #     self.logger.title(color+"        !!! Interface compatibility detected !!!         ")
        #     self.logger.title(color+"-----------------------------------------------------")
        #     # self.logger.title(color+"SWC-ID:   "+str(self.unchecked_return_value_detector.swc_id))
        #     self.logger.title(color+"Severity: "+self.unchecked_return_value_detector.severity)
        #     self.logger.title(color+"-----------------------------------------------------")
        #     if self.source_map and self.source_map.get_buggy_line(pc):
        #         self.logger.title(color+"Source code line:")
        #         self.logger.title(color+"-----------------------------------------------------")
        #         line = self.source_map.get_location(pc)['begin']['line'] + 1
        #         column = self.source_map.get_location(pc)['begin']['column'] + 1
        #         self.logger.title(color+self.source_map.source.filename+":"+str(line)+":"+str(column))
        #         self.logger.title(color+self.source_map.get_buggy_line(pc))

        #         # 这里选择function 
        #         callerfunction=self.source_map.get_buggy_line(pc)
        #         spotSite=callerfunction.find(".")
                
        #         # todo spotSite位置的判断

        #         kuohaoSite=callerfunction.find("(",spotSite)
        #         calledfunction=callerfunction[spotSite+1:kuohaoSite]

        #         self.logger.title(color+"-----------------------------------------------------")
        #     self.logger.title(color+"Transaction sequence:")
        #     self.logger.title(color+"-----------------------------------------------------")
        #     print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)


        # 新增uncheck_token_type的检测
        pc, index = self.uncheck_token_type.detect_uncheck_token_type(tainted_record, current_instruction, transaction_index)
        if pc and DetectorExecutor.add_error(errors, pc, "Uncheck Token Type", individual, mfe, self.unchecked_return_value_detector, self.source_map):
            color = DetectorExecutor.get_color_for_severity(self.uncheck_token_type.severity)
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"        !!! Uncheck Token Type detected !!!         ")
            self.logger.title(color+"-----------------------------------------------------")
            # self.logger.title(color+"SWC-ID:   "+str(self.unchecked_return_value_detector.swc_id))
            self.logger.title(color+"Severity: "+self.uncheck_token_type.severity)
            self.logger.title(color+"-----------------------------------------------------")
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+"Source code line:")
                self.logger.title(color+"-----------------------------------------------------")
                line = self.source_map.get_location(pc)['begin']['line'] + 1
                column = self.source_map.get_location(pc)['begin']['column'] + 1
                self.logger.title(color+self.source_map.source.filename+":"+str(line)+":"+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))

                # 这里选择function 
                callerfunction=self.source_map.get_buggy_line(pc)
                spotSite=callerfunction.find(".")
                
                # todo spotSite位置的判断

                kuohaoSite=callerfunction.find("(",spotSite)
                calledfunction=callerfunction[spotSite+1:kuohaoSite]

                self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"Transaction sequence:")
            self.logger.title(color+"-----------------------------------------------------")
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)


        # 新增初始化错误



        
        pc, index = self.init_error.detect_init_error(current_instruction, tainted_record, transaction_index,self.contract_dict,self.source_map)
        if pc and DetectorExecutor.add_error(errors, pc, "Init Error", individual, mfe, self.unprotected_selfdestruct_detector, self.source_map):
            color = DetectorExecutor.get_color_for_severity(self.init_error.severity)
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"      !!! Init Error detected !!!      ")
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"SWC-ID:   "+str(self.init_error.swc_id))
            self.logger.title(color+"Severity: "+self.init_error.severity)
            self.logger.title(color+"-----------------------------------------------------")
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+"Source code line:")
                self.logger.title(color+"-----------------------------------------------------")
                line = self.source_map.get_location(pc)['begin']['line'] + 1
                column = self.source_map.get_location(pc)['begin']['column'] + 1
                self.logger.title(color+self.source_map.source.filename+":"+str(line)+":"+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))
                self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"Transaction sequence:")
            self.logger.title(color+"-----------------------------------------------------")
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)




        pc, index = self.unprotected_selfdestruct_detector.detect_unprotected_selfdestruct(current_instruction, tainted_record, individual, transaction_index)
        if pc and DetectorExecutor.add_error(errors, pc, "Unprotected Selfdestruct", individual, mfe, self.unprotected_selfdestruct_detector, self.source_map):
            color = DetectorExecutor.get_color_for_severity(self.unprotected_selfdestruct_detector.severity)
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"      !!! Unprotected selfdestruct detected !!!      ")
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"SWC-ID:   "+str(self.unprotected_selfdestruct_detector.swc_id))
            self.logger.title(color+"Severity: "+self.unprotected_selfdestruct_detector.severity)
            self.logger.title(color+"-----------------------------------------------------")
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+"Source code line:")
                self.logger.title(color+"-----------------------------------------------------")
                line = self.source_map.get_location(pc)['begin']['line'] + 1
                column = self.source_map.get_location(pc)['begin']['column'] + 1
                self.logger.title(color+self.source_map.source.filename+":"+str(line)+":"+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))
                self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"Transaction sequence:")
            self.logger.title(color+"-----------------------------------------------------")
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)


        pc, index = self.unsafe_delegatecall_detector.detect_unsafe_delegatecall(current_instruction, tainted_record, individual, previous_instruction, transaction_index)
        if pc and DetectorExecutor.add_error(errors, pc, "Unsafe Delegatecall", individual, mfe, self.unsafe_delegatecall_detector, self.source_map):
            color = DetectorExecutor.get_color_for_severity(self.unsafe_delegatecall_detector.severity)
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"        !!! Unsafe delegatecall detected !!!         ")
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"SWC-ID:   "+str(self.unsafe_delegatecall_detector.swc_id))
            self.logger.title(color+"Severity: "+self.unsafe_delegatecall_detector.severity)
            self.logger.title(color+"-----------------------------------------------------")
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+"Source code line:")
                self.logger.title(color+"-----------------------------------------------------")
                line = self.source_map.get_location(pc)['begin']['line'] + 1
                column = self.source_map.get_location(pc)['begin']['column'] + 1
                self.logger.title(color+self.source_map.source.filename+":"+str(line)+":"+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))
                self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"Transaction sequence:")
            self.logger.title(color+"-----------------------------------------------------")
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)

        pc, index = self.leaking_ether_detector.detect_leaking_ether(current_instruction, tainted_record, individual, transaction_index, previous_branch)
        if pc and DetectorExecutor.add_error(errors, pc, "Leaking Ether", individual, mfe, self.leaking_ether_detector, self.source_map):
            color = DetectorExecutor.get_color_for_severity(self.leaking_ether_detector.severity)
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"           !!! Leaking ether detected !!!            ")
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"SWC-ID:   "+str(self.leaking_ether_detector.swc_id))
            self.logger.title(color+"Severity: "+self.leaking_ether_detector.severity)
            self.logger.title(color+"-----------------------------------------------------")
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+"Source code line:")
                self.logger.title(color+"-----------------------------------------------------")
                line = self.source_map.get_location(pc)['begin']['line'] + 1
                column = self.source_map.get_location(pc)['begin']['column'] + 1
                self.logger.title(color+self.source_map.source.filename+":"+str(line)+":"+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))
                self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"Transaction sequence:")
            self.logger.title(color+"-----------------------------------------------------")
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)

        pc, index = self.locking_ether_detector.detect_locking_ether(mfe.cfg, current_instruction, individual, transaction_index)
        if pc and DetectorExecutor.add_error(errors, pc, "Locking Ether", individual, mfe, self.locking_ether_detector, self.source_map):
            color = DetectorExecutor.get_color_for_severity(self.locking_ether_detector.severity)
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"           !!! Locking ether detected !!!            ")
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"SWC-ID:   "+str(self.locking_ether_detector.swc_id))
            self.logger.title(color+"Severity: "+self.locking_ether_detector.severity)
            self.logger.title(color+"-----------------------------------------------------")
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+"Source code line:")
                self.logger.title(color+"-----------------------------------------------------")
                line = self.source_map.get_location(pc)['begin']['line'] + 1
                column = self.source_map.get_location(pc)['begin']['column'] + 1
                self.logger.title(color+self.source_map.source.filename+":"+str(line)+":"+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))
                self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"Transaction sequence:")
            self.logger.title(color+"-----------------------------------------------------")
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)

        pc, index = self.unprotected_selfdestruct_detector.detect_unprotected_selfdestruct(current_instruction, tainted_record, individual, transaction_index)
        if pc and DetectorExecutor.add_error(errors, pc, "Unprotected Selfdestruct", individual, mfe, self.unprotected_selfdestruct_detector, self.source_map):
            color = DetectorExecutor.get_color_for_severity(self.unprotected_selfdestruct_detector.severity)
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"      !!! Unprotected selfdestruct detected !!!      ")
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"SWC-ID:   "+str(self.unprotected_selfdestruct_detector.swc_id))
            self.logger.title(color+"Severity: "+self.unprotected_selfdestruct_detector.severity)
            self.logger.title(color+"-----------------------------------------------------")
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+"Source code line:")
                self.logger.title(color+"-----------------------------------------------------")
                line = self.source_map.get_location(pc)['begin']['line'] + 1
                column = self.source_map.get_location(pc)['begin']['column'] + 1
                self.logger.title(color+self.source_map.source.filename+":"+str(line)+":"+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))
                self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"Transaction sequence:")
            self.logger.title(color+"-----------------------------------------------------")
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)


        pc, index = self.uncheck_address_parameter.detect_uncheck_address_parameter(tainted_record, current_instruction, transaction_index ,self.generator.fake_address)
        if pc and DetectorExecutor.add_error(errors, pc, "Uncheck Address Parameter detected", individual, mfe, self.unprotected_selfdestruct_detector, self.source_map):
            color = DetectorExecutor.get_color_for_severity(self.uncheck_address_parameter.severity)
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"      !!! Uncheck Address Parameter detected !!!      ")
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"SWC-ID:   "+str(self.uncheck_address_parameter.swc_id))
            self.logger.title(color+"Severity: "+self.uncheck_address_parameter.severity)
            self.logger.title(color+"-----------------------------------------------------")
            if self.source_map and self.source_map.get_buggy_line(pc):
                self.logger.title(color+"Source code line:")
                self.logger.title(color+"-----------------------------------------------------")
                line = self.source_map.get_location(pc)['begin']['line'] + 1
                column = self.source_map.get_location(pc)['begin']['column'] + 1
                self.logger.title(color+self.source_map.source.filename+":"+str(line)+":"+str(column))
                self.logger.title(color+self.source_map.get_buggy_line(pc))
                self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"Transaction sequence:")
            self.logger.title(color+"-----------------------------------------------------")
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)

        # 新增签名验证缺失
        pc, index = self.signature_verification_missing.detect_signature_verification_missing(tainted_record, current_instruction, transaction_index)
        if pc and DetectorExecutor.add_error(errors, pc, "Signature Verification Missing", individual, mfe, self.unprotected_selfdestruct_detector, self.source_map):
            color = DetectorExecutor.get_color_for_severity(self.signature_verification_missing.severity)
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"      !!! Signature Verification Missing detected !!!      ")
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"SWC-ID:   "+str(self.signature_verification_missing.swc_id))
            self.logger.title(color+"Severity: "+self.signature_verification_missing.severity)
            self.logger.title(color+"-----------------------------------------------------")
            self.logger.title(color+"Transaction sequence:")
            self.logger.title(color+"-----------------------------------------------------")
            print_individual_solution_as_transaction(self.logger, individual.solution, color, self.function_signature_mapping, index)


