#include <iostream>
#include <inttypes.h>

#include <capstone/capstone.h>


#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"

int main()
{
    csh handle;
    cs_insn* insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return -1;
    }

    count = cs_disasm(handle, reinterpret_cast<const uint8_t*>(CODE), sizeof(CODE) - 1, 0x10000000, 0, &insn);

    if (count > 0) {
        for (int i = 0; i < count; ++i) {
            printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
        }
    } else {
        printf("ERROR: Failed to disassemble given code!\n");
    }

    cs_close(&handle);

    return 0;
}