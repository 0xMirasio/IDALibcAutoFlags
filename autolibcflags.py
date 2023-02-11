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

        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def main(self):
        print(f"AutoLibcFlags {VERSION}")
    
    def run(self, arg):
        self.main()


def PLUGIN_ENTRY():
    return AutoLibcFlags()