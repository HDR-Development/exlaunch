// #include <stratosphere.hpp>
#include "lib.hpp"
#include <cstdint>

Result svcQueryMemoryHook(MemoryInfo* info, u32* page_info, uint64_t ptr) {
    auto result = svcQueryMemory(info, page_info, ptr);
    if (result == 0) {
        if (info->addr == reinterpret_cast<u64>(exl::util::modules::GetSelfStart())) {
            info->perm = 2;
        }
    }
    return result;
}

static Handle SM_HANDLE = 0xFFFFFFFF;

Result svcConnectToNamedPortHook(Handle* output_handle, const char* name) {
    auto result = svcConnectToNamedPort(output_handle, name);
    if (result == 0) {
        SM_HANDLE = *output_handle;
    }
    return result;
}

static const std::uint8_t SVC_QUERY_MEMORY_BYTES[] = {
    0xe1, 0x0f, 0x1f, 0xf8, 0xc1, 0x00, 0x00, 0xd4
};

static const std::uint8_t SVC_CONNECT_TO_NAMED_PORT_BYTES[] = {
    0xe0, 0x0f, 0x1f, 0xf8, 0xe1, 0x03, 0x00, 0xd4
};

/* This byte search is the only one that is a little iffy, this works back to 10.0 but if this fails in the future */
/* we will need to find a better way to locate this function */
static const std::uint8_t RECENTER_GC_STICK_BYTES[] = {
    0x08, 0x00, 0x40, 0x79, 
    0x29, 0x00, 0x40, 0x79, 
    0x08, 0x01, 0x09, 0x4b, 
    0x09, 0x04, 0x40, 0x79, 
    0x2a, 0x04, 0x40, 0x79, 
    0x29, 0x01, 0x0a, 0x4b, 
    0x28, 0x7d, 0x60, 0xb3, 
    0xe0, 0x03, 0x08, 0xaa, 
    0xc0, 0x03, 0x5f, 0xd6 
};

/* Simple byte search code that will search for a sequence of bytes in the .text region and return it as an offset */
/* if it was found */
uintptr_t find_offset(const std::uint8_t* ptr, std::size_t size) {
    const auto& info = exl::util::GetMainModuleInfo();
    const std::uint8_t* end = reinterpret_cast<const std::uint8_t*>(info.m_Text.m_Start + info.m_Text.m_Size - size);
    const std::uint8_t* start = reinterpret_cast<const std::uint8_t*>(info.m_Text.m_Start);
    while (start != end) {
        if (memcmp(start, ptr, size) == 0)
            return reinterpret_cast<uintptr_t>(start) - info.m_Text.m_Start;
        start++;
    }
    return 0;
}

/* Simple byte search code that will search for a sequence of bytes in the .text region and return it as a pointer */
/* if it was found */
uintptr_t find_pointer(const std::uint8_t* ptr, std::size_t size) {
    const auto& info = exl::util::GetMainModuleInfo();
    const std::uint8_t* end = reinterpret_cast<const std::uint8_t*>(info.m_Text.m_Start + info.m_Text.m_Size - size);
    const std::uint8_t* start = reinterpret_cast<const std::uint8_t*>(info.m_Text.m_Start);
    while (start != end) {
        if (memcmp(start, ptr, size) == 0)
            return reinterpret_cast<uintptr_t>(start);
        start++;
    }
    return 0;
}

/* A bit of a deceptive name, this will find the first bl instruction after another bl instruction that jumps to target */
/* If you pass a non-zero value for count, it will do this check count times */
uintptr_t find_offset_that_calls(uintptr_t target, size_t count) {
    /* Get our .text region to iterate through */
    const auto& info = exl::util::GetMainModuleInfo();
    const std::uint8_t* end = reinterpret_cast<const std::uint8_t*>(info.m_Text.m_Start + info.m_Text.m_Size - 4);
    const std::uint8_t* start = reinterpret_cast<const std::uint8_t*>(info.m_Text.m_Start);

    /* Whether we the next BL we find is the one we are returning */
    bool find_next = false;

    while (start != end) {
        /* Grab our instruction */
        const std::int32_t instruction = *reinterpret_cast<const uint32_t*>(start);

        /* Check if our instruction is bl */
        const auto opcode = (instruction & 0xFC000000) >> 24;
        if (opcode != 0x94) {
            /* If it is not, continue on */
            start += 4;
            continue;
        }

        /* Grab the offset and perform a sign extension on it if it is signed */
        const int32_t u_offset = instruction & 0x3FFFFFF;
        int32_t offset = 0;
        if ((u_offset & 0x2000000) != 0) {
            offset = 0xFC000000 | u_offset;
        } else {
            offset = u_offset;
        }

        /* If this is the one that we want to return, then return it as an offset */
        if (find_next) {
            return static_cast<uintptr_t>(reinterpret_cast<intptr_t>(start) + (offset * 4)) - info.m_Text.m_Start;
        }

        /* If it is not the one that we want to return, check if it points to the target address */
        /* and if it does, either decrement count or mark the next bl instruction as the one we are searching for */
        if (static_cast<uintptr_t>(reinterpret_cast<intptr_t>(start) + (offset * 4)) == target) {
            if (count == 0)
                find_next = true;
            else
                count--;
        }

        /* Continue on */
        start += 4;
    }

    return 0;
}

/* Finds the function that takes "hid:sys" as an argument on the x4 register*/
uintptr_t find_offset_for_hid_sys() {
    /* This mask + target combo is for finding an adrp instruction that loads to x4*/
    const uint32_t ADRP_MASK = 0x9F00001F;
    const uint32_t ADRP_TARGET = 0x90000004;

    /* This mask + target combo is for finding an add instruction of the form add x4, x4, #imm */
    const uint32_t ADD_MASK = 0xFFC003FF;
    const uint32_t ADD_TARGET = 0x91000084;

    /* This mask + target combo is for finding an instruction that is BL */
    const uint32_t BL_MASK = 0x9C000000;
    const uint32_t BL_TARGET = 0x94000000;

    /* Start by getting our .text region for main */
    const auto& info = exl::util::GetMainModuleInfo();
    const std::uint8_t* end = reinterpret_cast<const std::uint8_t*>(info.m_Text.m_Start + info.m_Text.m_Size - 4);
    const std::uint8_t* start = reinterpret_cast<const std::uint8_t*>(info.m_Text.m_Start);

    /* We also want these, because when we encounter a BL instruction we want to see if our x4 register is in a */
    /* state where we can safely dereference it without causing a panic */
    const auto& rodata = info.m_Rodata;
    const auto& data = info.m_Data;

    /* The x4 register that we are going to pseudo-emulate */
    uint64_t x_4_register = 0;

    while (start != end) {
        /* Fetch the instruction at our current offset */
        const std::uint32_t instruction = *reinterpret_cast<const uint32_t*>(start);

        if ((instruction & ADRP_MASK) == ADRP_TARGET) {
            /* If we have confirmed that it is an adrp instruction, fetch the offset from the current PC that it is going to be */
            /* loading into x4 and reconstruct it */
            uint64_t imm_lo = static_cast<uint64_t>((instruction & 0x60000000) >> 29);
            uint64_t imm_hi = static_cast<uint64_t>((instruction & 0x00FFFFE0) >> 5);
            uint64_t addr = (imm_lo << 12) | (imm_hi << 14);

            /* Mimic the adrp instruction to edit our x4 register, note that this is an assignment instead of an add-assign */
            x_4_register = (addr + (reinterpret_cast<uint64_t>(start) & ~0xFFF));
        } else if ((instruction & ADD_MASK) == ADD_TARGET) {
            /* Easier, if we have an add instruction then just pull out the immediate value and add it to our x4 register */
            uint64_t imm = static_cast<uint64_t>((instruction & 0x003FFC00) >> 10);
            x_4_register += imm;
        } else if ((instruction & BL_MASK) == BL_TARGET) {
            /* A little bit harder but we've done this before, since it's a BL instruction, mask out the imm bits*/
            const int32_t u_offset = instruction & 0x3FFFFFF;
            int32_t offset = 0;

            /* Check if the offset is negative for sign extension */
            if ((u_offset & 0x2000000) != 0) {
                /* Perform a sign extension on the immediate so when we add it to our address it is a proper offset */
                offset = 0xFC000000 | u_offset;
            } else {
                offset = u_offset;
            }

            /* Calculate the offset from the start of main to where we are jumping */
            const uintptr_t hid_sys_offset = static_cast<uintptr_t>(reinterpret_cast<intptr_t>(start) + (offset * 4)) - info.m_Text.m_Start;

            /* Check if the x4 register is in a dereferencable state, and if it is check if it contains "hid:sys" */
            if (rodata.Contains(static_cast<uintptr_t>(x_4_register)) || data.Contains(static_cast<uintptr_t>(x_4_register))) {
                if (*reinterpret_cast<const uint64_t*>(x_4_register) == *reinterpret_cast<const uint64_t*>("hid:sys")) {
                    return hid_sys_offset;
                }
            }
        }
        
        /* We didn't get what we want so keep moving */
        start += 4;
    }

    return 0;
}

uint64_t (*mapGcStick1)(int*, uint32_t, uint16_t*) = nullptr;
uint64_t (*mapGcStick2)(int*, uint32_t, uint16_t*) = nullptr;
int32_t (*hostService)(uint64_t, uint32_t, uint64_t, uint64_t, uint64_t) = nullptr;

static uint16_t MAXES[] = { 100, 100, 100, 100 };

static uint8_t THREAD_STACK[0x4000] = { 0 };

static bool SHOULD_FIX_STICKS = false;

uint64_t map_gc_stick1_hook(int* arg1, uint32_t arg2, uint16_t* arg3) {
    /* If we shouldn't be changing stick values, don't even bother with this */
    if (!SHOULD_FIX_STICKS) {
        return mapGcStick1(arg1, arg2, arg3);
    }

    /* Check if our deadzones are close enough to the gamecube ones to warrant changing */
    /* Even if this isn't a gamecube controller, these deadzones are hella shitty */
    if ((arg3[0] < 100) && (arg2 < 30)) {
        return mapGcStick1(arg1, 10, MAXES);
    } else {
        /* If it's not a GC controller (adjacent) then just use the defaults */
        return mapGcStick1(arg1, arg2, arg3);
    }
}

/* This function's docs are the same as the above */
uint64_t map_gc_stick2_hook(int* arg1, uint32_t arg2, uint16_t* arg3) {
    if (!SHOULD_FIX_STICKS) {
        return mapGcStick2(arg1, arg2, arg3);
    }

    if ((arg3[0] < 100) && (arg2 < 30)) {
        return mapGcStick2(arg1, 10, MAXES);
    } else {
        return mapGcStick2(arg1, arg2, arg3);
    }
}

static uint8_t FAILURE_REASON = 0;

/* This service hosts our hid:hdr service that is used to enable and disable stick gate changes */
/* only when HDR is running*/
void hdr_service_thread(void*) {

    /* Begin by creating our TLS buffer for the IPC command to the ServiceManager */
    /* to begin hosting our service */
    std::uint32_t* tls = reinterpret_cast<std::uint32_t*>(armGetTls());
    tls[0] = 0x4;
    tls[1] = 0xC;
    tls[2] = 0;
    tls[3] = 0;
    tls[4] = 0x49434653;
    tls[5] = 1;
    tls[6] = 2;
    tls[7] = 0;
    for (int i = 0; i < 8; i++) {
        reinterpret_cast<uint8_t*>(tls + 8)[i] = "hid:hdr"[i];
    }
    *reinterpret_cast<bool*>(tls + 10) = false;
    tls[11] = 100;

    /* Wait until sm gets back to us, silently fail if we fail */
    /* We can only fail here in normal circumstances if our handle for SM wasn't initialized (it should be by this point, since this runs after our hook */
    /* that sets it) */
    if (R_FAILED(svcSendSyncRequest(SM_HANDLE))) {
        return;
    }

    /* Parse out the service handle and the result from the buffer */
    const std::uint8_t* tls2 = reinterpret_cast<const std::uint8_t*>(armGetTls());
    Handle service_handle = *reinterpret_cast<const Handle*>(tls2 + 0xC);
    Result result = *reinterpret_cast<const Result*>(tls2 + 0x18);

    /* If our request failed, silently fail. It most likely means that the user does not have the modded main.npdm so that we can host our hid:hdr service */
    if (R_FAILED(result)) {
        return;
    }

    while (true) {
        /* Index required for the svc return value */
        s32 index = 0;

        /* Clear our TLS buffer */
        std::memset(armGetTls(), 0, 0x100);

        /* Wait until there is an incoming session connection for our service */
        /* Abort if failed, this should never fail, as it should only fail on an invalid handle or a timeout, both of which aren't happening here */
        R_ABORT_UNLESS(svcWaitSynchronization(&index, &service_handle, 1, U64_MAX));

        /* Accept our session, this should never fail because we have guaranteed that there is a session waiting to be accepted */
        Handle session_handle;
        R_ABORT_UNLESS(svcAcceptSession(&session_handle, service_handle));

        /* Clear our TLS buffer and wait for our session to send us a message */
        std::memset(armGetTls(), 0, 0x100);
        Result r = svcReplyAndReceive(&index, &session_handle, 1, INVALID_HANDLE, U64_MAX);
        while (true) {
            /* We get this error code if our session has been closed, so exit this while loop */
            if (r == 0xf601) {
                break;
            /* If that was not our error code, then abort because something has gone terribly wrong */
            /* Aborting at this stage is fine, it should force an atmosphere panic message and that allows */
            /* the user to give us more valuable feedback. We are only trying to avoid panics that will infinitely stall */
            /* the loading of the switch */
            } else if (r != 0) {
                EXL_ABORT(r);
            }

            /* Get our TLS and extract our command ID */
            u32* tls = reinterpret_cast<u32*>(armGetTls());
            u32 cmd = tls[6];

            switch (cmd) {
            /* Command ID 0 is for enabling (or disabling) our stick changes. */
            case 0:
                SHOULD_FIX_STICKS = tls[8] != 0;
                tls[0] = 0x0;
                tls[1] = 0x8;
                tls[2] = 0;
                tls[3] = 0;
                tls[4] = 0x4F434653;
                tls[5] = 0;
                tls[6] = 0;
                tls[7] = 0;
                tls[8] = 0;
                tls[9] = 0;
                break;
            /* Command ID 1 is for fetching the status of the hid:hdr mod, if it has failed then FAILURE_REASON will be non-zero */
            case 1:
                tls[0] = 0x0;
                tls[1] = 0x8;
                tls[2] = 0;
                tls[3] = 0;
                tls[4] = 0x4F434653;
                tls[5] = 0;
                tls[6] = 0;
                tls[7] = 0;
                tls[8] = FAILURE_REASON;
                tls[9] = 0;
                tls[10] = 0;
                break;

            /* On any other command, we abort */
            default:
                EXL_ABORT(cmd);
                break;
            }

            /* Wait for another message from our client */
            r = svcReplyAndReceive(&index, &session_handle, 1, session_handle, U64_MAX);
        }

        // TODO: Properly close the session 

        SHOULD_FIX_STICKS = false;
    }
}

/* Hooks the service hosting method so that we can hijack it to run our hid:hdr service */
int32_t hostServiceHook(uint64_t arg0, uint32_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4) {
    /* This function is only called from the main thread, so this doesn't even need to be atomic to ensure */
    /* that there is no race condition here */
    static bool DID_RUN = false;

    /* If we already ran then we have no need to re-host our service */
    if (DID_RUN) {
        return hostService(arg0, arg1, arg2, arg3, arg4);
    }

    /* Ensure we don't run again */
    DID_RUN = true;

    /* Host the service that the base module wants to host */
    /* If this fails, we're already in a shitty spot so there's no reason to check it, the user's system won't boot */
    auto result = hostService(arg0, arg1, arg2, arg3, arg4);

    /* Create a thread to run our service on */
    Handle thread_handle;
    R_ABORT_UNLESS(svcCreateThread(
        &thread_handle,
        reinterpret_cast<void*>(hdr_service_thread),
        nullptr,
        reinterpret_cast<void*>(THREAD_STACK + sizeof(THREAD_STACK)),
        12,
        3
    ));

    /* Start our thread, this shouldn't fail in normal circumstances */
    R_ABORT_UNLESS(svcStartThread(thread_handle));

    return result;
}

extern "C" void exl_main(void* x0, void* x1) {
    /* Setup hooking enviroment. */
    envSetOwnProcessHandle(exl::util::proc_handle::Get());
    exl::hook::Initialize();

    /* Query memory hook MUST NOT fail, but it most likely is stable since these instructions are written by hand as inline asm */
    auto query_mem_offset = find_offset(SVC_QUERY_MEMORY_BYTES, sizeof(SVC_QUERY_MEMORY_BYTES));

    exl::hook::HookFunc(query_mem_offset, svcQueryMemoryHook, false);

    /* Connect to named port hook also most likely will not fail, however if it does we will be unable to host a service at all */
    /* and can inform the user of that via the game side */
    auto connect_to_named_port_offset = find_offset(SVC_CONNECT_TO_NAMED_PORT_BYTES, sizeof(SVC_CONNECT_TO_NAMED_PORT_BYTES));

    /* Same reasoning applies to this offset, if we can't find this offset then we are unable to host our service */
    auto hid_sys = find_offset_for_hid_sys();

    /* If we can't find the offsets, don't even bother searching for the rest since we won't be able to turn them on */
    if ((connect_to_named_port_offset == 0) || (hid_sys == 0)) {
        /* No point in setting FAILURE_REASON here since the game cannot query or it */
        return;
    }

    exl::hook::HookFunc(connect_to_named_port_offset, svcConnectToNamedPortHook, false);
    hostService = reinterpret_cast<int32_t(*)(uint64_t, uint32_t, uint64_t, uint64_t, uint64_t)>(exl::hook::HookFunc(hid_sys, hostServiceHook, true));

    auto recenter_gc_sticks = find_pointer(RECENTER_GC_STICK_BYTES, sizeof(RECENTER_GC_STICK_BYTES));

    /* If we can't find the offset, just set our failure reason, which can be queried from the hid:hdr service */
    if (recenter_gc_sticks == 0) {
        FAILURE_REASON = 1;
        return;
    }

    /* We need two hooks, one of which will be for gamecube controller, the other will be for non-gamecube controller */
    /* We have logic written above to determine which one to activate at runtime, but for now we don't have the memory layout guarantee */
    /* for which one comes first, so we hook both. */
    auto first = find_offset_that_calls(recenter_gc_sticks, 0);

    if (first == 0) {
        FAILURE_REASON = 2;
        return;
    }

    auto second = find_offset_that_calls(recenter_gc_sticks, 1);

    if (second == 0) {
        FAILURE_REASON = 3;
        return;
    }

    mapGcStick1 = reinterpret_cast<uint64_t(*)(int*, uint32_t, uint16_t*)>(exl::hook::HookFunc(first, map_gc_stick1_hook, true));
    mapGcStick2 = reinterpret_cast<uint64_t(*)(int*, uint32_t, uint16_t*)>(exl::hook::HookFunc(second, map_gc_stick2_hook, true));

    FAILURE_REASON = 0;

    exl::hook::CallTargetEntrypoint(x0, x1);
}

extern "C" NORETURN void exl_exception_entry() {
    /* TODO: exception handling */
    svcReturnFromException(0xf801);
}