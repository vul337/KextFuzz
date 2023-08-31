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

    logger.info("[*] edit got {} -> {}".format(ori_sym, new_sym))
    
    return kext_bytes

def edit_bytes(kext_bytes: bytes, start: int, length: int, new: list):
    if (len(new) != length):
        logger.error("len(new) != len")
        exit()

    new_bytes = b''.join([(i).to_bytes(1, byteorder="little") for i in new])

    kext_bytes = kext_bytes[:start] + new_bytes + kext_bytes[start + length:]
    return kext_bytes

def edit_inst(ori_bin: bytes, addr: int, inst_s: str):
    inst_b = ks.asm(inst_s)[0]
    # logger.debug("[*] edit_bin: {}, {}".format(hex(addr), str(inst_b)))
    return edit_bytes(ori_bin, addr, len(inst_b), inst_b)

'''
|- edit end
'''

def type_check(kext_bytes: bytes) -> bool:
    if kext_bytes[:4] != b'\xcf\xfa\xed\xfe' or kext_bytes[4:8] != b'\x0c\x00\x00\x01': # check magic and cputype
        return False
    return True

def find_stub(kext_bytes: bytes, sym: str) -> int:
    n_loadcmd = int.from_bytes(kext_bytes[0x10: 0x14], byteorder = 'little')
    logger.debug("[*] parsing kext binary files")

    stub_ptr = 0
    dylib_sym_start_idx = 0

    sym_table = []
    str_table = b''

    cnt = 0
    cur_ptr = 0x20

    while cnt < n_loadcmd:
        cmd_magic = kext_bytes[cur_ptr: cur_ptr+4]
        cmd_size = int.from_bytes(kext_bytes[cur_ptr+4: cur_ptr+8], byteorder = 'little')
        seg_name = kext_bytes[cur_ptr + 8: cur_ptr + 0x18]
        # logger.debug("    |- cmd_magic 0x%s, cmd_size 0x%x" % (cmd_magic, cmd_size))

        if cmd_magic == b'\x19\x00\x00\x00' and seg_name.startswith(b'__TEXT_EXEC'): # LC_SEGMENT_64
            sec_num = int.from_bytes(kext_bytes[cur_ptr+0x40: cur_ptr+0x44], byteorder = 'little')
            for i in range(sec_num):
                sec_ptr = cur_ptr+0x48+i*0x50 # 0x50: sec size
                sec_name = kext_bytes[sec_ptr: sec_ptr + 0x50]
                if b'_stubs' in sec_name:
                    stub_ptr = int.from_bytes(kext_bytes[sec_ptr + 0x30: sec_ptr + 0x34], byteorder = 'little')
                    logger.debug("[*] stub section at: %s" % hex(stub_ptr))

        elif cmd_magic == b'\x0b\x00\x00\x00': # LC_DYSYMTAB
            dysym_off = int.from_bytes(kext_bytes[cur_ptr + 0x38: cur_ptr + 0x3c], byteorder = 'little') 
            dysym_entries = int.from_bytes(kext_bytes[cur_ptr + 0x3c: cur_ptr + 0x40], byteorder = 'little')

            dysym_table_bin = [kext_bytes[dysym_off+i*4: dysym_off+i*4+4] for i in range(dysym_entries)]
            dysym_table = [int.from_bytes(i, byteorder='little') for i in dysym_table_bin]

        elif cmd_magic == b'\x02\x00\x00\x00': # LC_SYMTAB
            sym_table_ptr = int.from_bytes(kext_bytes[cur_ptr + 0x8 : cur_ptr + 0xc], byteorder = 'little')
            n_sym = int.from_bytes(kext_bytes[cur_ptr + 0xc : cur_ptr + 0x10], byteorder = 'little')
           

            str_table_ptr = int.from_bytes(kext_bytes[cur_ptr + 0x10 : cur_ptr + 0x14], byteorder = 'little')
            str_table_size = int.from_bytes(kext_bytes[cur_ptr + 0x14 : cur_ptr + 0x18], byteorder = 'little')
            str_table = kext_bytes[str_table_ptr: str_table_ptr + str_table_size]

            sym_table = [kext_bytes[sym_table_ptr+i*0x10: sym_table_ptr+i*0x10+0x10] for i in range(n_sym)]

        cnt += 1
        cur_ptr += cmd_size

    for idx, sym_index in enumerate(dysym_table):
        sym_entry = sym_table[sym_index]
        str_off = int.from_bytes(sym_entry[0:4], byteorder = 'little')

        sym_str = str_table[str_off - 1: str_off + len(sym) + 1]
        if sym_str == b'\x00' + sym + b'\x00':
            tgt_idx = idx
            break
        
    stub_addr = stub_ptr + tgt_idx * 0xc


    return stub_addr

def find_text(kext_bytes: bytes) -> (int, int):
    ncmds = int.from_bytes(kext_bytes[0x10:0x14], byteorder = 'little', signed=False)

    cmd_ptr = 0x20
    for i in range(ncmds):
        cmd = int.from_bytes(kext_bytes[cmd_ptr: cmd_ptr + 0x4], 'little')
        cmdsize = int.from_bytes(kext_bytes[cmd_ptr + 0x4: cmd_ptr + 0x8], 'little')

        if cmd == 0x19:
            segname = kext_bytes[cmd_ptr + 0x8: cmd_ptr + 0x8 + 0x4 * 4]
            if segname.startswith(b'__TEXT'):
                sec_ptr = cmd_ptr + 0x48
                while sec_ptr < cmd_ptr + cmdsize:
                    
                    sectname = kext_bytes[sec_ptr: sec_ptr + 0x4 * 4]
                    if sectname.startswith(b'__text'):
                        fileoff = int.from_bytes(kext_bytes[sec_ptr + 48: sec_ptr + 52], 'little')
                        filesize = int.from_bytes(kext_bytes[sec_ptr + 40: sec_ptr + 48], 'little')

                        return fileoff, fileoff + filesize
                    sec_ptr += 0x50

        cmd_ptr += cmdsize

    return -1, -1

def find_vtable_pa(kext_bytes: bytes, start: int, end: int) -> list:
    tmp_cnt_blraa = 0
    tmp_cnt_braa = 0

    '''
    find pattern:
        CMP             X16, X17
        B.EQ            loc_3ABCC
        BRK             #0xC472
    '''
    res = []
    for ptr in range(start, end, 4):
        '''
        find following pattern
         CMP  X16, X17
         B.EQ xxxxxx
         BRK  #0xC472
        '''
        if kext_bytes[ptr: ptr + 4] == b'\x1F\x02\x11\xEB':
            if kext_bytes[ptr + 4: ptr + 8] == b'\x40\x00\x00\x54':
                if kext_bytes[ptr + 8: ptr + 12] == b'\x40\x8E\x38\xD4':
                    # if kext_bytes[ptr - 4: ptr] == b'\xF1\x47\xC1\xDA':
                        '''
                        filter out function call uses BRAA (make sure x30 has been saved)
                        '''
                        for i in range(ptr + 12, ptr + 12 + 4 * 10, 4):
                            if kext_bytes[i+2:i+4] == b'\x3f\xd7': # BLRAA
                                res.append(ptr)
                                tmp_cnt_blraa += 1
                                break
                            elif kext_bytes[i+2:i+4] == b'\x1f\xd7': # BRAA
                                tmp_cnt_braa += 1
                                break

    logger.info("[*] tmp_cnt_blraa %d, tmp_cnt_braa %d, percent: %f" % (tmp_cnt_blraa, tmp_cnt_braa, tmp_cnt_braa * 1.0/ tmp_cnt_blraa))
    return res


def instrument_vtable_pa(kext_bytes: bytes, fileoff: int, filend: int, stub_addr: int) -> bytes:
    # search vtable pac list
    pac_list = find_vtable_pa(kext_bytes, fileoff, filend)
    logger.info("[*] len(vtable_pac_list): {}".format(len(pac_list)))

    logger.info("    |- note: vtable_pa_list[0:5]: {}".format([hex(i) for i in pac_list[0:5]]))
    logger.info("    |- note: vtable_pa_list[-5:]: {}".format([hex(i) for i in pac_list[-5:]]))
    logger.info("    |- note stub_addr {}".format(hex(stub_addr)))

    # test: patch to nop
    i_nop = [31, 32, 3, 213]
    for pac in pac_list:
        kext_bytes = edit_inst(kext_bytes, pac, "nop")
        kext_bytes = edit_inst(kext_bytes, pac + 4, "BL #{}".format(stub_addr - (pac + 4)))
        kext_bytes = edit_inst(kext_bytes, pac + 8, "mov x16, x17")

    return kext_bytes

def find_x30_pa(kext_bytes: bytes, start: int, end: int) -> list:
    pacibsp_list = []
    autibsp_list = []
    retab_list = []
    # instru_list = []

    for ptr in range(start, end, 4):
        if kext_bytes[ptr: ptr + 4] == b'\x7F\x23\x03\xD5': # PACIBSP
            pacibsp_list.append(ptr)
        elif kext_bytes[ptr: ptr + 4] == b'\xFF\x23\x03\xD5': # AUTIBSP
            autibsp_list.append(ptr)
        elif kext_bytes[ptr: ptr + 4] == b'\xFF\x0F\x5F\xD6': # RETAB
            retab_list.append(ptr)


    return pacibsp_list, autibsp_list, retab_list

def instrument_x30_pa(kext_bytes: bytes, fileoff: int, filend: int, stub_addr: int) -> bytes:
    pacibsp_list, autibsp_list, retab_list = find_x30_pa(kext_bytes, fileoff, filend)
    logger.info("[*] x30_pa len(pacibsp_list): {}".format(len(pacibsp_list)))
    logger.info("[*] x30_pa len(autibsp_list): {}".format(len(autibsp_list)))
    logger.info("[*] x30_pa len(retab_list): {}".format(len(retab_list)))

    logger.info("    |- note: pacibsp_list[0:5]: {}".format([hex(i) for i in pacibsp_list[0:5]]))
    logger.info("    |- note: autibsp_list[0:5]: {}".format([hex(i) for i in autibsp_list[0:5]]))
    logger.info("    |- note: retab_list[0:5]: {}".format([hex(i) for i in retab_list[0:5]]))

    for ptr in pacibsp_list:
        edit_inst(kext_bytes, ptr, "nop")

        # search max nine insts
        tgt = 0
        for p in range(ptr + 4, ptr + 4 * 15, 4):
            if kext_bytes[p+3: p+4] == b'\xd1': # SUB xx
                continue
            elif kext_bytes[p: p+2] == b'\xFD\x7B' and kext_bytes[p+3: p+4] == b'\xA9': # STP X29, X30, [SP,#0xn]
                tgt = p
                break
            elif kext_bytes[p: p+1] == b'\xFE' and kext_bytes[p+3: p+4] == b'\xF9': # e.g. STR X30, [SP]
                tgt = p
                break
            elif kext_bytes[p+3: p+4] == b'\xA9' or kext_bytes[p+3: p+4] == b'\x6d': # 0x6d: e.g. STP D9, D8, [SP,#-0x10+var_40]! 0xa9: e.g. STP X24, X23, [SP,#0x40+var_30]
                continue
            else:
                # break
                continue

        if tgt:
            cov_inst = ks.asm("BL #{}".format(stub_addr - (tgt)))[0]
            cov_inst_bytes = b''.join([(i).to_bytes(1, byteorder="little") for i in cov_inst])
            kext_bytes = kext_bytes[:ptr] + kext_bytes[ptr+4: tgt+4] + cov_inst_bytes + kext_bytes[tgt+4:]
        else:
            logger.error("[-] x30 not on the stack? {}".format(hex(ptr)))
            exit()

    for ptr in autibsp_list:
        if kext_bytes[ptr + 12: ptr + 16] == b"\x20\x8E\x38\xD4":
            '''
            e.g. 
            autibsp
            EOR  X9, X30, X30,LSL#1
            TBZ  X9, #0x3E, loc_100E4
            BRK  #0xC471
            ''' 
            edit_inst(kext_bytes, ptr, "nop")
            edit_inst(kext_bytes, ptr + 4, "nop")
            edit_inst(kext_bytes, ptr + 8, "nop")
            edit_inst(kext_bytes, ptr + 12, "nop")
        elif kext_bytes[ptr + 4: ptr + 8] == b"\xC0\x03\x5F\xD6":
            '''
            autibsp
            ret
            '''
            edit_inst(kext_bytes, ptr, "nop")
        else:
            edit_inst(kext_bytes, ptr, "nop")
            logger.debug("unknown autibsp pattern: ptr {}".format(hex(ptr)))

    for retab in retab_list:
        edit_inst(kext_bytes, retab, "ret")


    return kext_bytes

def edit(kext_bytes: bytes, ori_sym, hooker_sym, sym_addrs: list, stub_addr) -> bytes:
    # find text segment range
    fileoff, filend = find_text(kext_bytes)
    logger.debug("[*] start instrumentation, text_start: {}, text_end: {}".format(hex(fileoff), hex(filend)))


    kext_bytes = edit_got(kext_bytes, ori_sym, hooker_sym, sym_addrs)

    # instrument by replacing vtable ptr pa instruction
    kext_bytes = instrument_vtable_pa(kext_bytes, fileoff, filend, stub_addr)

    ## instrument by replacing x30 pa (PACIBSP) instuction, not stable in some cases ##
    kext_bytes = instrument_x30_pa(kext_bytes, fileoff, filend, stub_addr)

    return kext_bytes

def edit_pac(kext_bytes: bytes, sym_pairs):
    if len(kext_bytes) == 0:
        logger.error("len(kext_bytes) == 0")
        exit(0)

    ori_sym = b''
    hooker_sym = b''

    for pair in sym_pairs:
        _ori_sym = pair['ori_sym']
        _hooker_sym = pair['hooker_sym']

        if len(_ori_sym) != len(_hooker_sym):
            logger.error('[-] len(ori_sym) != len(hooker_sym), ({}, {})'.format(_ori_sym, _hooker_sym))

        if kext_bytes.find(b'\x00' + _ori_sym.encode('utf-8') + b'\x00') != -1:
            ori_sym = _ori_sym.encode('utf-8')
            hooker_sym = _hooker_sym.encode('utf-8')

    if ori_sym:
        tgt = b'\x00' + ori_sym + b'\x00'
        addr0 = kext_bytes.find(tgt) + 1
        addr1 = kext_bytes.rfind(tgt) + 1
    else:
        logger.error('[-] None of the ori symbol has been found. Check the "symbol-pair" entry in config file')
        exit(0)

    stub_addr = find_stub(kext_bytes, ori_sym)
    logger.info('[+] target stub_addr 0x%x' % stub_addr)
    kext_bytes = edit(kext_bytes, ori_sym, hooker_sym, (addr0, addr1), stub_addr)

    return kext_bytes

if __name__ == "__main__":
    logger.remove()
    logger.add(sys.stdout, level = "DEBUG")

    binp_prefix = "./xx/"
    in_p = binp_prefix + 'xx'
    out_p = in_p + '_covd'

    with open(in_p, 'rb') as f:
        bin_data = f.read()
        bin_data = edit_pac(bin_data)

    with open(out_p, "wb") as f:
        f.write(bin_data)
        f.close()

    st = os.stat(out_p)
    os.chmod(out_p, st.st_mode | 0b111101101)

    logger.info("[+] SAVED IN: {}".format(out_p))