import os
import json

from loguru import logger
from keystone import *
from capstone import *

import sys

ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

'''
|- edit
'''
def edit_got(kext_bytes: bytes, ori_sym: bytes, new_sym: bytes, addrs: list):
    if len(ori_sym) != len(new_sym):
        logger.error("len(ori_sym) != len(new_sym)")
        exit()
    
    for addr in addrs:
        if kext_bytes[addr: addr + len(ori_sym)] != ori_sym:
            logger.error("addr:{} kext_bytes[addr: addr + len(ori_sym)] != ori_sym {}".format(hex(addr), kext_bytes[addr: addr + len(ori_sym)]))
            exit()
            
        kext_bytes = kext_bytes[:addr] + new_sym + kext_bytes[addr + len(ori_sym): ]

    logger.info("[+] edit got {} -> {}".format(ori_sym, new_sym))
    
    return kext_bytes

def edit_inst(ori_bin: bytes, addr: int, inst_s: str):
    inst_b = ks.asm(inst_s)[0]
    logger.debug("[+] edit_bin: {}, {}".format(hex(addr), str(inst_b)))
    return edit_bytes(ori_bin, addr, len(inst_b), inst_b)

'''
|- edit end
'''

def type_check(kext_bytes: bytes) -> bool:
    if kext_bytes[:4] != b'\xcf\xfa\xed\xfe' or kext_bytes[4:8] != b'\x0c\x00\x00\x01': # check magic and cputype
        return False
    return True

def edit_entitle(kext_bytes: bytes) -> bin:
    sym = b'__ZN12IOUserClient21copyClientEntitlementEP4taskPKc'
    addr0 = kext_bytes.find(sym)
    addr1 = kext_bytes.rfind(sym)
    if addr0 != -1:
        logger.info("%s founded" % sym)
        kext_bytes = edit_got(kext_bytes, sym, b'__ZN12IOFuzzClient21copyClientEntitlementEP4taskPKc', [addr0, addr1])
    else:
        logger.info("%s not founded, do not need patch" % sym)

    sym = b'__ZN24AppleMobileFileIntegrity16copyEntitlementsEP4proc'
    addr0 = kext_bytes.find(sym)
    addr1 = kext_bytes.rfind(sym)
    if addr0 != -1:
        logger.info("%s founded" % sym)
        kext_bytes = edit_got(kext_bytes, sym, b'__ZN12IOFuzzClient25AMFIcopyClientEntitlementEP4taskPKc', [addr0, addr1])
    else:
        logger.info("%s not founded, do not need patch" % sym)

    return kext_bytes


if __name__ == "__main__":
    logger.remove()
    logger.add(sys.stdout, level = "DEBUG")

    binp_prefix = "../xx/"
    bin_n = "xx"

    in_p = binp_prefix + bin_n
    out_p = in_p + "_symentitled"

    with open(in_p, 'rb') as f:
        kext_bytes = f.read()

    if not type_check(kext_bytes):
        logger.error("[-] Mach-O file only")
        exit()

    kext_bytes = entitle_edit(kext_bytes)

    with open(out_p, "wb") as f:
        f.write(kext_bytes)
        f.close()

    st = os.stat(out_p)
    os.chmod(out_p, st.st_mode | 0b111101101)

    logger.info("[+] edited kext saved in {}".format(out_p))