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
import platform
import ida_typeinf
import ida_enum

VERSION="1.0"
p_initialized = False
#--------------------------------------------------------------------------
# Plugin
#--------------------------------------------------------------------------
class AutoLibcFlags(idaapi.plugin_t):
    comment = "Print comment on Flags enum/explanation near libc function call"
    help = "AutoLibcFlags Help"
    wanted_name = "AutoLibcFlags"
    flags = idaapi.PLUGIN_KEEP | idaapi.PLUGIN_MOD | idaapi.PLUGIN_PROC
    wanted_hotkey= "Ctrl+Shift+F1"


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

        if platform.system() == 'Windows':
            self.enum_cache = os.path.join(os.environ['APPDATA'], 'IdaAutoLibcFlags')
            self.os = 'win'
        elif platform.system() == 'Linux':
            self.enum_cache == os.path.join(os.environ['HOME'] ,".cache/IdaAutoLibcFlags")
            self.os = 'linux'
        else:
            print('[IDAAutoLibcFlags] Unknown operating system | Not supported')
            return

        if os.path.exists(self.enum_cache):
            return 0
        else:
            print("Didn't not find enum cache ! Please install plugins with ./install.sh | ./install.bat script")
            return 1

    def registerFunctionSupported(self):
        filepath = os.path.join(self.enum_cache, "functions.json")
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
        root = idaapi.get_std_dirtree(idaapi.DIRTREE_ENUMS)

        #todo : check we are IDA > 7.4 , if not we can't use get_std_dirtree()
        err = root.mkdir("IDAAutoLibcFlags")
        if err not in (idaapi.DTE_OK, idaapi.DTE_ALREADY_EXISTS):
            print(f'Could not create IDAAutoLibcFlags structures directory: "{root.errstr(err)}"')
            return 1
        
        for enum in self.enum:

            if ida_enum.get_enum(enum) != idaapi.BADNODE: #cleanup old enums
                ida_enum.del_enum(ida_enum.get_enum(enum))
                    
            idaenum = idc.add_enum(-1, enum, 0)
            if idaenum == idaapi.BADADDR:
                print("Couldn't not create enum")
                return 1

            number_added = 0
            
            err = root.rename(enum, f"IDAAutoLibcFlags/{enum}")
            if err not in (idaapi.DTE_OK, idaapi.DTE_ALREADY_EXISTS, idaapi.DTE_NOT_FOUND):
                print(f'Could not moove {enum} into IDAAutoLibcflags directory: "{root.errstr(err)}"')
                return 1

            for enum_value, enum_member_name in self.enum[enum]:
                err = idc.add_enum_member(idaenum, enum_member_name, int(enum_value), -1)
                if err:
                    print(f'Could not populate {enum} on {enum_member_name} = {enum_value}  : err = {err}')
                
                number_added += 1


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
                enum_name = "{0}".format(self.functions_libc_supported[fun][i][1])
                if enum_name == idc.BADADDR:
                    print("Enum : {0} don't exist !".format(enum_name))
                    continue
                

                for ea in idautils.Functions():
                    addr_patch = self.lookupFunction(ea, fun)
                    print(fun, addr_patch)

                    if len(addr_patch) == 0:
                        continue
                    

                    for address in addr_patch:
                        arg_addr = self.find_args_with_index(index,address)
                        if arg_addr:
                            enumida = idaapi.get_enum(enum_name)
                            r = idc.op_enum(arg_addr, 1, enumida, 0)
                            if (r == -1): #sometime IDA just fail.
                                r = idc.op_enum(arg_addr, 1, enumida, 0)



    def main(self):
        print(f"AutoLibcFlags {VERSION}")
        if self.sanityCheck():
            return -1

        self.registerFunctionSupported()
        print("Registered all functions")
        self.ImportEnum()
        print("Imported Know enums")

        if self.AddEnum():
            return -1
        print("Done caching Enum definitions to IDB")
        self.applyEnum()
        print("Done Applying Enum DATA. Use F5 to refresh page cache")
        
    def run(self, arg):
        self.main()


def PLUGIN_ENTRY():
    return AutoLibcFlags()