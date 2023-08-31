import sys
import os
import plistlib as pllib
import shutil
import json

from loguru import logger

from edit_entitle import edit_entitle
from edit_pac import edit_pac

def lipo(bin_p: str) -> bytes:
    '''
    lipo arm from fat mach-o
    '''
    FAT_MAGIC = 0xcafebabe.to_bytes(4, byteorder = 'big')
    FAT_MAGIC_64 = 0xcafebabf.to_bytes(4, byteorder = 'big')
    MH_MAGIC_64 = b'\xcf\xfa\xed\xfe'
    CPU_TYPE_X86_64 = 0x01000007.to_bytes(4, byteorder = 'big')
    CPU_TYPE_ARM64 = b'\x01\x00\x00\x0c'
    CPU_TYPE_ARM64_2 = b'\x0c\x00\x00\x01'

    with open(bin_p, 'rb') as f:
        kext_bytes = f.read()

    magic = kext_bytes[0:4]

    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        logger.info("ori binary type: Fat Mach-O")
        arch_n = int.from_bytes(kext_bytes[4:8], byteorder = 'big')
        for i in range(arch_n):
            arch_header = kext_bytes[8+i*20: 8+(i+1)*20]
            cputype = arch_header[0:4]
            
            if cputype == CPU_TYPE_ARM64:
                offset = int.from_bytes(arch_header[8:12], byteorder = 'big')
                size = int.from_bytes(arch_header[12:16], byteorder = 'big')
                return kext_bytes[offset: offset + size]

    
    elif magic == MH_MAGIC_64:
        logger.info("ori binary type: Mach-O")
        cpu_type = kext_bytes[4:8]
        if cpu_type in (CPU_TYPE_ARM64, CPU_TYPE_ARM64_2):
            return kext_bytes    

    logger.error("no suitable arch type")
    logger.error(magic)
    logger.error(cpu_type)
    exit(0)
    return None

def rewrite(bin_p: str, sym_pair, entitle = 1, cov = 1):
    kext_bytes = lipo(bin_p)

    if entitle:
        if bin_p.endswith("AppleMobileFileIntegrity"):
            logger.error("Entitlement check in AppleMobileFileIntegrity can not be patched")
        else:
            kext_bytes = edit_entitle(kext_bytes)
        
    if cov:
        kext_bytes = edit_pac(kext_bytes, sym_pair)

    return kext_bytes

def save_bin(kext_bytes: bytes, out_p: str):
    if not kext_bytes:
        logger.error("kext_bytes is null")
        exit(0)

    with open(out_p, "wb") as f:
        f.write(kext_bytes)
        f.close()

    st = os.stat(out_p)
    os.chmod(out_p, st.st_mode | 0b111101101)

    logger.info("[+] edited bin saved in {}".format(out_p))

def edit_plist(ori_plist_p: str, new_plist_p: str, helper_bundle):
    with open(ori_plist_p, 'rb') as fp:
        pl = pllib.load(fp)

    pl["OSBundleLibraries"][helper_bundle] = '1.0'
    
    with open(new_plist_p, 'wb') as fp:
        pllib.dump(pl, fp)

    logger.info("add covioctl dependency to %s" % new_plist_p)

def cp_kext_path(input_dir: str, output_dir: str, tgt: str, helper_bundle: str):
    # find info.plist
    ori_tgt = os.path.join(input_dir, tgt)
    plist_dir = os.path.dirname(ori_tgt)
    ori_plist_p = ''
    while plist_dir:
        if os.path.exists(plist_dir + '/Info.plist'):
            ori_plist_p = plist_dir + '/Info.plist'
            break
        plist_dir = os.path.dirname(plist_dir)
    if not ori_plist_p:
        logger.error('info.plist not found')
        exit(0)

    # copy root path
    parkext = tgt.split('/')[0]
    if not parkext.endswith('.kext'):
        logger.error("invalid tgt path (should ends with .kext): tgt path %s" % tgt)
        exit(0)

    ori_kext_p = os.path.join(input_dir, parkext)
    new_kext_p = os.path.join(output_dir, parkext)
    if not os.path.exists(new_kext_p):
        shutil.copytree(ori_kext_p, new_kext_p)
    
    # edit info.plist
    new_plist_p = ori_plist_p.replace(input_dir, output_dir)
    edit_plist(ori_plist_p, new_plist_p, helper_bundle)

    return os.path.join(input_dir, tgt)
        

if __name__ == '__main__':
    logger.remove()
    logger.add(sys.stdout, level = "INFO")

    if len(sys.argv) != 2:
        logger.error('usage: python kext_rewrite.py <config-file-path>')
        logger.error('e.g. python kext_rewrite.py ./config.json')
        exit(0)

    with open(sys.argv[1]) as f:
        cfg = json.load(f)

    if (cfg['cov-rewrite'] or cfg['entitle-rewrite']) and not cfg['helper-kext-bundle']:
        logger.error('[config]: "helper-kext-bundle" can not be none')
        exit(0)

    if cfg['cov-rewrite'] and not cfg['symbol-pair']:
        logger.error('[config]: "symbol-pair" can not be none for cov-rewrite')
        exit(0)

    for pair in cfg['symbol-pair']:
        if len(pair['ori_sym']) != len(pair['hooker_sym']):
            logger.error('[-] cfg["symbol-pair"] {}: len(ori_sym) != len(hooker_sym)'.format(pair))

    for tgt in cfg['patch-targets']:
        if not os.path.exists(os.path.join(cfg["input_dir"], tgt)):
            logger.error('[-] target not exist ({})'.format(os.path.join(os.path.join(cfg["input_dir"], tgt))))
            exit(0)

        logger.info('[+] edit binary %s' % tgt)
        in_p = cp_kext_path(cfg['input_dir'], cfg['output_dir'], tgt, cfg['helper-kext-bundle'])
        bin_data = rewrite(in_p, sym_pair = cfg['symbol-pair'], cov = cfg['cov-rewrite'], entitle = cfg['entitle-rewrite'])
        out_p = os.path.join(cfg['output_dir'], tgt)
        save_bin(bin_data, out_p)