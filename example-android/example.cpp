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
    
    ElfScanner g_il2cppElf{};
    // loop until our target library is found
    do
    {
        sleep(1);
        // get loaded elf
        g_il2cppElf = kittyMemMgr.getMemElf("libil2cpp.so");
    } while (!g_il2cppElf.isValid());
    
    uintptr_t il2cppBase = g_il2cppElf.base();
    KITTY_LOGI("libil2cpp.so base: %p", (void *)il2cppBase);

    
    KITTY_LOGI("================ MEMORY READ & WRITE ===============");

    // read & write memory (address, buffer, buffer_size)
    char magic[16] = {0};
    size_t bytesRead = kittyMemMgr.readMem(il2cppBase, magic, sizeof(magic));
    KITTY_LOGI("bytesRead: 0x%zx", bytesRead);
    // size_t bytesWritten = kittyMemMgr.writeMem(il2cppBase, magic, sizeof(magic));
    // KITTY_LOGI("bytesWritten: 0x%zx", bytesRead);

    // read & write string from memory (magic + 1) = "ELF"
    // kittyMemMgr.readMemStr(il2cppBase + 1, 3);
    // kittyMemMgr.writeMemStr(il2cppBase + 1, magic + 1, 3);


    KITTY_LOGI("==================== SYMBOL LOOKUP ===================");

    KITTY_LOGI("il2cpp elf valid = %d", g_il2cppElf.isValid() ? 1 : 0);
    KITTY_LOGI("il2cpp_string_new = %p", (void *)g_il2cppElf.findSymbol("il2cpp_string_new"));


    KITTY_LOGI("==================== MEMORY PATCH ===================");

    // let's assume we have patches for these functions for whatever game
    // boolean function
    MemoryPatch get_canShoot;
    // int function
    MemoryPatch get_gold;
    // etc...

    // with bytes, must specify bytes count
    get_canShoot = kittyMemMgr.memPatch.createWithBytes(il2cppBase + 0x10948D4, "\x01\x00\xA0\xE3\x1E\xFF\x2F\xE1", 8);
    // hex with or without spaces both are fine
    get_canShoot = kittyMemMgr.memPatch.createWithHex(il2cppBase + 0x10948D4, "01 00 A0 E3 1E FF 2F E1");
    // (uses keystone assembler) insert ';' to seperate statements
    // its recommeneded to test your instructions on https://armconverter.com or https://shell-storm.org/online/Online-Assembler-and-Disassembler/
    // change MP_ASM_ARM64 to your targeted asm arch
    // MP_ASM_ARM32, MP_ASM_ARM64, MP_ASM_x86, MP_ASM_x86_64
    get_canShoot = kittyMemMgr.memPatch.createWithAsm(il2cppBase + 0x10948D4, MP_ASM_ARM64, "mov x0, #1; ret");

    // format asm
    auto asm_fmt = KittyUtils::String::Fmt("mov x0, #%d; ret", 65536);
    get_gold = kittyMemMgr.memPatch.createWithAsm(il2cppBase + 0x10948D4, MP_ASM_ARM64, asm_fmt);

    KITTY_LOGI("Patch Address: %p", (void *)get_canShoot.get_TargetAddress());
    KITTY_LOGI("Patch Size: %zu", get_canShoot.get_PatchSize());
    KITTY_LOGI("Current Bytes: %s", get_canShoot.get_CurrBytes().c_str());

    // modify & print bytes
    if (get_canShoot.Modify())
    {
        KITTY_LOGI("get_canShoot has been modified successfully");
        KITTY_LOGI("Current Bytes: %s", get_canShoot.get_CurrBytes().c_str());
    }

    // restore & print bytes
    if (get_canShoot.Restore())
    {
        KITTY_LOGI("get_canShoot has been restored successfully");
        KITTY_LOGI("Current Bytes: %s", get_canShoot.get_CurrBytes().c_str());
    }


    KITTY_LOGI("==================== MEMORY DUMP ====================");

    std::string dumpFolder = KittyUtils::getExternalStorage();
    bool isDumped = false;

    // dump memory elf
    std::string sodumpPath = dumpFolder + "/il2cpp_dump.so";
    isDumped = kittyMemMgr.dumpMemELF(il2cppBase, sodumpPath);
    KITTY_LOGI("il2cpp so dump = %d", isDumped ? 1 : 0);

    // dump memory file
    std::string datdumpPath = dumpFolder + "/global-metadata.dat";
    isDumped = kittyMemMgr.dumpMemFile("global-metadata.dat", datdumpPath);
    KITTY_LOGI("metadata dump = %d", isDumped ? 1 : 0);


    KITTY_LOGI("==================== PATTERN SCAN ===================");

    // scan within a memory range for bytes with mask x and ?

    uintptr_t found_at = 0;
    std::vector<uintptr_t> found_at_list;

    uintptr_t search_start = g_il2cppElf.baseSegment().startAddress;
    uintptr_t search_end = g_il2cppElf.baseSegment().endAddress;

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

    KITTY_LOGI("libc [ remote_mmap = %p | remote_munmap = %p ]", (void*)remote_mmap, (void*)remote_munmap);

    // mmap(nullptr, KT_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uintptr_t mmap_ret = kittyMemMgr.trace.callFunction(remote_mmap, 6,
                                                    nullptr, KT_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    // munmap(mmap_ret, KT_PAGE_SIZE);
    uintptr_t munmap_ret = kittyMemMgr.trace.callFunction(remote_munmap, 2, mmap_ret, KT_PAGE_SIZE);

    KITTY_LOGI("Remote call [ mmap_ret=%p | munmap_ret=%p ]", (void*)mmap_ret, (void*)munmap_ret);

    kittyMemMgr.trace.Detach();

    return 0;
}