import idaapi
import idc
import sys
import idautils
import ida_funcs
import time
import os
import subprocess
import sys
from collections import defaultdict
import ida_hexrays
import json

VERSION="1.0"
p_initialized = False
#--------------------------------------------------------------------------
# Plugin
#--------------------------------------------------------------------------
class AutoLibcFlags(idaapi.plugin_t):
    comment = "Print comment on Flags enum/explanation near libc function call"
    help = "AutoLibcFlags Help"
    wanted_name = "AutoLibcFlags"
    flags = idaapi.PLUGIN_KEEP
    wanted_hotkey= "Ctrl+Shift-Z"


    def init(self):
        global p_initialized
        if p_initialized is False:
            p_initialized = True
            idaapi.register_action(idaapi.action_desc_t(
                "AutoLibcFlags",
                "AutoLibcFlags imports",
                None,
                None,
                None,
                0))
            print(f"AutoLibcFlags {VERSION} | Thibault Poncetta")
            self.enum = {}

        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def sanityCheck(self):
        user = os.getenv("USER")
        self.enum_cache = "/home/" + user + "/.cache/AutoLibcFlags"
        if os.path.exists(self.enum_cache):
            return 0
        else:
            print("Didn't not find enum cache ! Please install plugins with ./install.sh script")
            return 1

    def registerFunctionSupported(self):
        filepath = os.path.join(self.enum_cache, "functions.json")
        print(filepath)
        with open(filepath) as fd:
            self.functions_libc_supported = json.load(fd)


    def ImportEnum(self):
      
        for filename in os.listdir(self.enum_cache):
            filepath = os.path.join(self.enum_cache, filename)
            if os.path.isfile(filepath) and "functions.json" not in filename:
                with open(filepath, 'r') as f:
                    self.enum[filename] = []
                    for line in f:
                        enum_value, enum_name = line.strip().split(" ")
                        self.enum[filename].append([enum_value, enum_name])

    def AddEnum(self):
        for enum in self.enum:
            enum_name =  "AutoLibc_{0}".format(enum)
            idaenum = idc.add_enum(-1, enum_name, 0)
            number_added = 0
            for enum_value, enum_member_name in self.enum[enum]:
                idc.add_enum_member(idaenum, enum_member_name, int(enum_value), -1)
                number_added += 1
            print("{0} : Added a total of {1} members".format(enum, number_added))


    def lookupFunction(self, ea, name):
        
        addr = []
        for instr in idautils.FuncItems(ea):
            r = idaapi.is_call_insn(instr)
            if r:
                for r in idautils.XrefsFrom(instr, 1):
                    f_name = idc.get_func_name(r.to).replace(".","") #remove plt prefix
                    if f_name == name:
                        addr.append(instr)
        return addr

    def find_args_with_index(self, index, call_address):
        call_args_x64 = {0 : "rdi", 1 : "rsi", 2 : "rdx", 3 : "rcx", 4 : "r8d"}

        mnem_search = call_args_x64[index]
        mnem_search_32b = mnem_search.replace("r","e")
        max_reverse_limit = 5

        cpt=1
        ea = call_address
        
        for i in range(max_reverse_limit):
            ea = idc.prev_head(ea, 0)
            mnem = idc.print_insn_mnem(ea)
            if mnem == "mov":
                op = idc.print_operand(ea,0)
                if op == mnem_search or op == mnem_search_32b:
                    return ea

        return None
        

    def applyEnum(self):

        for fun in self.functions_libc_supported:

            for i in range(len(self.functions_libc_supported[fun])):

                index = self.functions_libc_supported[fun][i][0]
                enum_name = "AutoLibc_{0}".format(self.functions_libc_supported[fun][i][1])
                if enum_name == idc.BADADDR:
                    print("Enum : {0} don't exist !".format(enum_name))
                    continue

                for ea in idautils.Functions():
                    addr_patch = self.lookupFunction(ea, fun)
                    if len(addr_patch) == 0:
                        continue

                    for address in addr_patch:
                        arg_addr = self.find_args_with_index(index,address)
                        if arg_addr:
                            enumida = idaapi.get_enum(enum_name)
                            print("[debug] trns {0} for {1} at {2}".format(enum_name, fun, hex(arg_addr)))
                            r = idc.op_enum(arg_addr, 1, enumida, 0)
                            if (r == -1): #sometime IDA just fuck it and fail. But it's fine they tell it in their documentation :))))
                                idc.op_enum(arg_addr, 1, enumida, 0)



    def main(self):
        print(f"AutoLibcFlags {VERSION}")
        if self.sanityCheck():
            return -1

        self.registerFunctionSupported()
        print("Registered all functions")

        self.ImportEnum()
        self.AddEnum()
        print("Done caching Enum definitions to IDB")
        self.applyEnum()
        
    def run(self, arg):
        self.main()


def PLUGIN_ENTRY():
    return AutoLibcFlags()