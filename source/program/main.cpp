// #include <stratosphere.hpp>
#include "lib.hpp"

Result svcQueryMemoryHook(MemoryInfo* info, u32* page_info, uint64_t ptr) {
    auto result = svcQueryMemory(info, page_info, ptr);
    if (result == 0) {
        if (info->addr == reinterpret_cast<u64>(exl::util::modules::GetSelfStart())) {
            info->perm = 2;
        }
    }
    return result;
}

static uint64_t (*mapGcStickOriginal)(int*, uint32_t, uint16_t*);

static bool s_WereHooksInstalled = false;
static bool s_ShouldFixSticks = false;
static u64 s_LastTickCount = 0;
static u64 s_LastTickStart = 0;
uint64_t mapGcStick(int* stick_vals, uint32_t stick_min, uint16_t* stick_maxes) {
    if (s_ShouldFixSticks) {
        stick_min = 10;
        stick_maxes[0] = 100;
        stick_maxes[1] = 100;
        stick_maxes[2] = 100;
        stick_maxes[3] = 100;
    }
    return mapGcStickOriginal(stick_vals, stick_min, stick_maxes);
}

static const std::uint8_t MAP_GC_STICK_BYTES[] = {
    0x09, 0x28, 0x40, 0x29, 0x28, 0x3c, 0x00, 0x12, 0xeb, 0x03, 0x08, 0x4b, 0x2c, 0x01, 0x08, 0x0b, 0x2d, 0x01, 0x08, 0x4b, 0x3f, 0x05, 0x00, 0x71
};

static const std::uint8_t SVC_QUERY_MEMORY_BYTES[] = {
    0xe1, 0x0f, 0x1f, 0xf8, 0xc1, 0x00, 0x00, 0xd4
};

static std::uint8_t LAST_PACKET[37] = { 0 };


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

Result poll_usb(uint8_t* buffer) {
    Result (*PollFn)(uintptr_t, uintptr_t, uintptr_t, u32, u32, u32) = reinterpret_cast<
        Result (*)(uintptr_t, uintptr_t, uintptr_t, u32, u32, u32)
    >(exl::util::modules::GetTargetOffset(0x1132f0));
    uintptr_t arg0 = exl::util::modules::GetTargetOffset(0x35f000);
    uintptr_t arg1 = exl::util::modules::GetTargetOffset(0x245760);
    uintptr_t arg2 = exl::util::modules::GetTargetOffset(0x245710);
    reinterpret_cast<u64*>(arg0)[0] = 0;
    auto res = PollFn(arg0, arg1, arg2, 0x25, 4, 0);
    if (res == 0) {
        std::memcpy(reinterpret_cast<void*>(buffer), reinterpret_cast<const void*>(arg2), 37);
    }
    return res;
}

void hdr_service_thread(void*) {
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

    Handle sm_handle = *reinterpret_cast<uint32_t*>(exl::util::modules::GetTargetOffset(0x35468c));

    R_ABORT_UNLESS(svcSendSyncRequest(sm_handle));

    const std::uint8_t* tls2 = reinterpret_cast<const std::uint8_t*>(armGetTls());
    Handle service_handle = *reinterpret_cast<const Handle*>(tls2 + 0xC);
    Result result = *reinterpret_cast<const Result*>(tls2 + 0x18);
    R_ABORT_UNLESS(result);

    while (true) {
        s32 index = 0;
        std::memset(armGetTls(), 0, 0x100);
        R_ABORT_UNLESS(svcWaitSynchronization(&index, &service_handle, 1, U64_MAX));

        Handle session_handle;
        R_ABORT_UNLESS(svcAcceptSession(&session_handle, service_handle));

        std::memset(armGetTls(), 0, 0x100);
        Result r = svcReplyAndReceive(&index, &session_handle, 1, INVALID_HANDLE, U64_MAX);
        while (true) {

            if (r == 0xf601) {
                break;
            } else if (r != 0) {
                EXL_ABORT(r);
            }

            u32* tls = reinterpret_cast<u32*>(armGetTls());

            u32 cmd = tls[6];

            switch (cmd) {
            case 0:
                tls[0] = 0x0;
                tls[1] = 0x9;
                tls[2] = 0;
                tls[3] = 0;
                tls[4] = 0x4F434653;
                tls[5] = 0;
                tls[6] = 0;
                tls[7] = 0;
                tls[8] = s_WereHooksInstalled ? 1 : 0;
                tls[9] = 0;
                tls[10] = 0;
                break;
            case 1:
                s_ShouldFixSticks = tls[8] != 0;
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
            case 2:
                tls[0] = 0x0;
                tls[1] = 0x12;
                tls[2] = 0;
                tls[3] = 0;
                *reinterpret_cast<u64*>(&tls[4]) = s_LastTickStart;
                *reinterpret_cast<u64*>(&tls[6]) = s_LastTickCount;
                std::memcpy(tls + 8, LAST_PACKET, 37);
                tls[18] = 0;
                tls[19] = 0;
                break;
            default:
                EXL_ABORT(cmd);
                break;
            }
            r = svcReplyAndReceive(&index, &session_handle, 1, session_handle, U64_MAX);
        }

        // R_ABORT_UNLESS(svcCloseHandle(session_handle));

        s_ShouldFixSticks = false;
    }
}

static Result (*HostServiceOriginal)(void* allocator, bool is_light, void* service_object, u32 max_sessions, const char* name);

static std::uint8_t THREAD_STACK[0x4000] = { 0 };

Result HostServiceHook(void* allocator, bool is_light, void* service_object, u32 max_sessions, const char* name) {
    static bool HAS_RUN = false;
    if (!HAS_RUN) {
        HAS_RUN = true;
        R_ABORT_UNLESS(HostServiceOriginal(allocator, is_light, service_object, max_sessions, name));

        Handle thread_handle;
        R_ABORT_UNLESS(
            svcCreateThread(
                &thread_handle,
                reinterpret_cast<void*>(hdr_service_thread),
                nullptr,
                reinterpret_cast<void*>(THREAD_STACK + sizeof(THREAD_STACK)),
                12,
                3
            )
        );

        R_ABORT_UNLESS(svcStartThread(thread_handle));
        return 0;
    }
    return HostServiceOriginal(allocator, is_light, service_object, max_sessions, name);
}

static Result (*ParseGcPacketOriginal)(void*, void*, uint8_t*, u32, u32, u32) = nullptr;

Result ParseGcPacketHook(void* a0, void* a1, uint8_t* a2, u32 a3, u32 a4, u32 a5) {
    auto tick = svcGetSystemTick();
    Result res = ParseGcPacketOriginal(a0, a1, a2, a3, a4, a5);
    auto end_tick = svcGetSystemTick();
    s_LastTickStart = tick;
    s_LastTickCount = end_tick - tick;
    if (a2[0] == 0x21) {
        std::memcpy(LAST_PACKET, a2, 37);
    }
    return res;
}

static void (*SetSleepOrig)(uint64_t*) = nullptr;

void SetSleepHook(uint64_t* ptr) {
    if (s_ShouldFixSticks) {
        ptr[6] = 0x4c4b40;
    } else {
        ptr[6] = 0x989680;
    }
    SetSleepOrig(ptr);
}

extern "C" void exl_main(void* x0, void* x1) {
    /* Setup hooking enviroment. */
    envSetOwnProcessHandle(exl::util::proc_handle::Get());
    exl::hook::Initialize();

    s_WereHooksInstalled = true;
    auto query_mem_offset = find_offset(SVC_QUERY_MEMORY_BYTES, sizeof(SVC_QUERY_MEMORY_BYTES));
    if (query_mem_offset == 0) {
        s_WereHooksInstalled = false;
    }
    auto map_gc_stick = find_offset(MAP_GC_STICK_BYTES, sizeof(MAP_GC_STICK_BYTES));
    if (map_gc_stick == 0)
        s_WereHooksInstalled = false;

    exl::hook::HookFunc(query_mem_offset, svcQueryMemoryHook, false);

    if (s_WereHooksInstalled)
        mapGcStickOriginal = exl::hook::HookFunc(map_gc_stick, mapGcStick, true);
    HostServiceOriginal = exl::hook::HookFunc(0x105600, HostServiceHook, true);
    ParseGcPacketOriginal = exl::hook::HookFunc(0x1132f0, ParseGcPacketHook, true);
    SetSleepOrig = exl::hook::HookFunc(0x7efa8, SetSleepHook, true);
    /* Install the hook at the provided function pointer. Function type is checked against the callback function. */

    /* Alternative install funcs: */
    /* InstallAtPtr takes an absolute address as a uintptr_t. */
    /* InstallAtOffset takes an offset into the main module. */

    /*
    For sysmodules/applets, you have to call the entrypoint when ready
    */
    exl::hook::CallTargetEntrypoint(x0, x1);
}

extern "C" NORETURN void exl_exception_entry() {
    /* TODO: exception handling */
    svcReturnFromException(0xf801);
}