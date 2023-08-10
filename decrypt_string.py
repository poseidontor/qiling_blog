from qiling import *
from qiling.const import QL_VERBOSE, QL_INTERCEPT
from qiling.os.const import STRING, SIZE_T, POINTER
from unicorn import UC_PROT_ALL, UC_MEM_WRITE
import struct


def prepare_for_emulation(ql,base_address):
    ql.mem.map(0x6d5a620000, 65536, UC_PROT_ALL, info = "[challenge]")
    ql.mem.map(0x120000, 65536, UC_PROT_ALL, info = "[challenge_2]")
    ql.mem.map(0x0, 1024, UC_PROT_ALL, info = "[challenge_3]")
    ql.arch.regs.write("sp", 0x6d5a620200)
    ql.arch.regs.write("x29", 0x6d5a620280)
    ql.arch.regs.write("x9", 0x555555554000)
    ql.arch.regs.write("x8", 0x0)
    #ql.mem.write(base_address+0xf50, struct.pack("<Q", base_address+0xa20))


def my_printf(ql: Qiling):
    params = ql.os.resolve_fcall_params({'s1': STRING , 's2': STRING})
    s1 = params['s1']
    s2 = params['s2']
    #ql.log.info(f'my_printf: got "{s1}" and "{s2}" as an argument')

def my_strlen(ql: Qiling):
    params = ql.os.resolve_fcall_params({'s': STRING})
    s = params['s']
    #ql.log.info(f'param to strlen: {s}')
    ql.arch.regs.write("x0", len(s))
    return len(s)

def my_strncat(ql: Qiling):
    params = ql.os.resolve_fcall_params({'s1': STRING , 's2': POINTER, 's3': SIZE_T})
    #s1 = params['s1']
    s2 = params['s2']
    s3 = params['s3']
    ff = ql.mem.read(s2,1)[0]
    addr = ql.arch.regs.read("x0")
    s1 = ql.mem.string(addr)
    #ql.log.info(f'Called strncat({s1},{chr(ff)},{s3})')
    s1 += chr(ff)
    ql.mem.string(addr,s1)
    return s1

def mem_write(ql: Qiling, access: int, address: int, size: int, value: int) -> None:
    # only write accesses are expected here
    assert access == UC_MEM_WRITE
    try:
        if ql.mem.is_mapped(value, 1024):
            decode_str = ql.mem.string(value)
            ql.log.debug(f'intercepted a memory write to {address:#x} (value = {decode_str})')
    except Exception:
        ql.log.debug(f'An error occured!')

def branch_transform(ql: Qiling) -> None:
    transform = 0x555555554000 + 0xa20
    ql.arch.regs.write("pc", transform)    
    #ql.log.debug(f'Hook address reached')

def read_decry_string(ql: Qiling) -> None:
    x0 = ql.arch.regs.read("x0")
    if ql.mem.is_mapped(x0,1024):
        t = ql.mem.string(x0)
        ql.log.debug(f'Decrypted String: {t}')
    
def branch_back_to_main(ql: Qiling) -> None:
    x0 = ql.arch.regs.read("x0")
    transform_output = ql.mem.string(x0)
    sp = ql.arch.regs.read("sp")
    #test = ql.mem.read(sp, 1)
    ret = 0x555555554000 + 0xbe0
    ql.arch.regs.write("pc", ret)
    #ql.log.debug(f"Return value of transform: {transform_output}")
    #ql.log.debug(f"Return to main activity")


def my_sandbox(path, rootfs):
    start_addr = 0xb80
    end_addr = 0xc08
    ql = Qiling(path, rootfs, verbose=QL_VERBOSE.DEBUG)
    base_address = int(ql.profile.get("OS64", "load_address"), 16)
    prepare_for_emulation(ql, base_address)
    #ql.hook_mem_write(mem_write)
    ql.hook_address(branch_transform, base_address + 0xbdc)
    ql.hook_address(read_decry_string, base_address + 0xb30)
    ql.hook_address(branch_back_to_main, base_address + 0xb38)
    ql.os.set_api('printf', my_printf, QL_INTERCEPT.CALL)
    ql.os.set_api('__strlen_chk', my_strlen, QL_INTERCEPT.CALL)
    ql.os.set_api('__strncat_chk', my_strncat, QL_INTERCEPT.CALL)
    ql.run(begin=base_address+start_addr, end=base_address+end_addr)

if __name__== "__main__":
    my_sandbox(["/home/krat0s/Downloads/qilingLab/libkeys.so"], "/home/krat0s/projects/qiling/qiling/examples/rootfs/arm64_android") 