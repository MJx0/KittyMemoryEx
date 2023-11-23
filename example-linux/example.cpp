#include <thread>

#include <string>
#include <cstdint>
#include <vector>

// include KittyMemory
#include "../KittyMemoryEx/KittyMemoryMgr.hpp"
KittyMemoryMgr kittyMemMgr;

int main(int argc, char *args[])
{
    // ./exe [target process name]
    if (argc < 2)
    {
        KITTY_LOGE("Missing arg (process name).");
        return 1;
    }

    std::string processName = args[1];
    // get process ID
    pid_t processID = KittyMemoryEx::getProcessID(processName);
    if (!processID)
    {
        KITTY_LOGI("Couldn't find process id of %s.", processName.c_str());
        return 1;
    }

    KITTY_LOGI("Process Name: %s", processName.c_str());
    KITTY_LOGI("Process ID: %d", processID);

    // initialize KittyMemoryMgr instance with process ID
    if (!kittyMemMgr.initialize(processID, EK_MEM_OP_SYSCALL, true))
    {
        KITTY_LOGI("Error occurred )':");
        return 1;
    }

    KITTY_LOGI("================ GET ELF BASE ===============");
    
    ElfScanner g_libcElf{};
    // loop until our target library is found
    do
    {
        sleep(1);
        // get loaded elf
        g_libcElf = kittyMemMgr.getMemElf("libc.so");
    } while (!g_libcElf.isValid());
    
    uintptr_t libcBase = g_libcElf.base();
    KITTY_LOGI("libc.so base: %p", (void *)libcBase);
    
    KITTY_LOGI("================ MEMORY READ & WRITE ===============");

    // read & write memory (address, buffer, buffer_size)
    char magic[16] = {0};
    size_t bytesRead = kittyMemMgr.readMem(libcBase, magic, sizeof(magic));
    KITTY_LOGI("bytesRead: 0x%zx", bytesRead);
    // size_t bytesWritten = kittyMemMgr.writeMem(libcBase, magic, sizeof(magic));
    // KITTY_LOGI("bytesWritten: 0x%zx", bytesRead);

    // read & write string from memory (magic + 1) = "ELF"
    // kittyMemMgr.readMemStr(libcBase + 1, 3);
    // kittyMemMgr.writeMemStr(libcBase + 1, magic + 1, 3);


    KITTY_LOGI("==================== SYMBOL LOOKUP ===================");

    KITTY_LOGI("libc elf valid = %d", g_libcElf.isValid() ? 1 : 0);

    uintptr_t remote_ptrace = g_libcElf.findSymbol("ptrace");
    KITTY_LOGI("libc remote_ptrace = %p", (void *)remote_ptrace);


    KITTY_LOGI("==================== MEMORY PATCH ===================");

    // disabling libc ptrace as an example
    MemoryPatch ptrace_patch;

    // with bytes, must specify bytes count
    ptrace_patch = kittyMemMgr.memPatch.createWithBytes(remote_ptrace, "\x48\xC7\xC0\x00\x00\x00\x00\xC3", 8);
    // hex with or without spaces both are fine
    ptrace_patch = kittyMemMgr.memPatch.createWithHex(remote_ptrace, "48 C7 C0 00 00 00 00 C3");
    // (uses keystone assembler) insert ';' to seperate statements
    // its recommeneded to test your instructions on https://armconverter.com or https://shell-storm.org/online/Online-Assembler-and-Disassembler/
    // change MP_ASM_ARM64 to your targeted asm arch
    // MP_ASM_ARM32, MP_ASM_ARM64, MP_ASM_x86, MP_ASM_x86_64
    //ptrace_patch = kittyMemMgr.memPatch.createWithAsm(remote_ptrace, MP_ASM_ARM64, "mov rax, 0; ret");

    // format asm
    //auto asm_fmt = KittyUtils::String::Fmt("mov x0, %d; ret", 0);
    //ptrace_patch = kittyMemMgr.memPatch.createWithAsm(remote_ptrace, MP_ASM_ARM64, asm_fmt);

    KITTY_LOGI("Patch Address: %p", (void *)ptrace_patch.get_TargetAddress());
    KITTY_LOGI("Patch Size: %zu", ptrace_patch.get_PatchSize());
    KITTY_LOGI("Current Bytes: %s", ptrace_patch.get_CurrBytes().c_str());

    // modify & print bytes
    if (ptrace_patch.Modify())
    {
        KITTY_LOGI("ptrace_patch has been modified successfully");
        KITTY_LOGI("Current Bytes: %s", ptrace_patch.get_CurrBytes().c_str());
    }

    // restore & print bytes
    if (ptrace_patch.Restore())
    {
        KITTY_LOGI("ptrace_patch has been restored successfully");
        KITTY_LOGI("Current Bytes: %s", ptrace_patch.get_CurrBytes().c_str());
    }


    KITTY_LOGI("==================== MEMORY DUMP ====================");

    std::string dumpFolder = ".";
    bool isDumped = false;

    // dump memory elf
    std::string sodumpPath = dumpFolder + "/libc_dump.so";
    isDumped = kittyMemMgr.dumpMemELF(libcBase, sodumpPath);
    KITTY_LOGI("libc so dump = %d", isDumped ? 1 : 0);


    KITTY_LOGI("==================== PATTERN SCAN ===================");

    // scan within a memory range for bytes with mask x and ?

    uintptr_t found_at = 0;
    std::vector<uintptr_t> found_at_list;

    uintptr_t search_start = g_libcElf.baseSegment().startAddress;
    uintptr_t search_end = g_libcElf.baseSegment().endAddress;

    KITTY_LOGI("search start %p", (void*)search_start);
    KITTY_LOGI("search end %p", (void*)search_end);

    // scan with direct bytes & get one result
    found_at = kittyMemMgr.memScanner.findBytesFirst(search_start, search_end, "\x33\x44\x55\x66\x00\x77\x88\x00\x99", "xxxx??x?x");
    KITTY_LOGI("found bytes at: %p", (void *)found_at);
    // scan with direct bytes & get all results
    found_at_list = kittyMemMgr.memScanner.findBytesAll(search_start, search_end, "\x33\x44\x55\x66\x00\x77\x88\x00\x99", "xxxx??x?x");
    KITTY_LOGI("found bytes results: %zu", found_at_list.size());

    // scan with hex & get one result
    found_at = kittyMemMgr.memScanner.findHexFirst(search_start, search_end, "33 44 55 66 00 77 88 00 99", "xxxx??x?x");
    KITTY_LOGI("found hex at: %p", (void *)found_at);
    // scan with hex & get all results
    found_at_list = kittyMemMgr.memScanner.findHexAll(search_start, search_end, "33 44 55 66 00 77 88 00 99", "xxxx??x?x");
    KITTY_LOGI("found hex results: %zu", found_at_list.size());

    // scan with ida pattern & get one result
    found_at = kittyMemMgr.memScanner.findIdaPatternFirst(search_start, search_end, "33 ? 55 66 ? 77 88 ? 99");
    KITTY_LOGI("found ida pattern at: %p", (void *)found_at);
    // scan with ida pattern & get all results
    found_at_list = kittyMemMgr.memScanner.findIdaPatternAll(search_start, search_end, "33 ? 55 66 ? 77 88 ? 99");
    KITTY_LOGI("found ida pattern results: %zu", found_at_list.size());

    // scan with data type & get one result
    uint32_t data = 0xdeadbeef;
    found_at = kittyMemMgr.memScanner.findDataFirst(search_start, search_end, &data, sizeof(data));
    KITTY_LOGI("found data at: %p", (void *)found_at);

    // scan with data type & get all results
    found_at_list = kittyMemMgr.memScanner.findDataAll(search_start, search_end, &data, sizeof(data));
    KITTY_LOGI("found data results: %zu", found_at_list.size());

    KITTY_LOGI("====================== HEX DUMP =====================");

    // hex dump by default 8 rows with ASCII
    KITTY_LOGI("\n%s", KittyUtils::HexDump(magic, sizeof(magic)).c_str());

    KITTY_LOGI("=================== HEX DUMP CUSTOM =================");

    // 16 rows, no ASCII
    KITTY_LOGI("\n%s", KittyUtils::HexDump<16, false>(magic, sizeof(magic)).c_str());


    KITTY_LOGI("================= PTRACE REMOTE CALL ===============");

    // check tracer
    int tracerPID = KittyMemoryEx::getStatusInteger(processID, "TracerPid");
    if (tracerPID > 0)
    {
        KITTY_LOGE("Process is being traced by another process with ID %d.", tracerPID);
        return 1;
    }

    if (!kittyMemMgr.trace.Attach())
    {
        KITTY_LOGE("Failed to attach.");
        return 1;
    }

    uintptr_t remote_mmap = kittyMemMgr.findRemoteOfSymbol(KT_LOCAL_SYMBOL(mmap));
    uintptr_t remote_munmap = kittyMemMgr.findRemoteOfSymbol(KT_LOCAL_SYMBOL(munmap));

    KITTY_LOGI("libc [ remote_mmap=%p | remote_munmap=%p ]", (void *)remote_mmap, (void*)remote_munmap);

    // mmap(nullptr, KT_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uintptr_t mmap_ret = kittyMemMgr.trace.callFunction(remote_mmap, 6,
                                                    nullptr, KT_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    // munmap(mmap_ret, KT_PAGE_SIZE);
    uintptr_t munmap_ret = kittyMemMgr.trace.callFunction(remote_munmap, 2, mmap_ret, KT_PAGE_SIZE);

    KITTY_LOGI("Remote mmap_ret=%p | munmap_ret=%p", (void*)mmap_ret, (void*)munmap_ret);

    kittyMemMgr.trace.Detach();

    return 0;
}