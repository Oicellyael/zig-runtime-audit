const std = @import("std");

extern "user32" fn GetAsyncKeyState(vKey: c_int) i16;
extern "kernel32" fn Sleep(dwMilliseconds: u32) void;

const VK_DELETE = 0x2E;

const MyUnicode = extern struct {
    Length: u16,
    MaximumLength: u16,
    Buffer: ?[*:0]const u16,
};

const List_entry = extern struct {
    Flink: ?*List_entry,
    Blink: ?*List_entry,
};

const Ldr_table = extern struct {
    InLoadOrderLinks: List_entry,
    RandomPaddingFirst: [32]u8,
    DllBase: ?*anyopaque,
    RandomPaddingSecond: [32]u8,
    BaseDllName: MyUnicode,
};

const Peb_Ldr_Data = extern struct {
    Reserved: [16]u8,
    InLoadOrderModuleList: List_entry,
};

const Peb = extern struct {
    RandomPaddingFirst: [24]u8,
    Ldr: ?*Peb_Ldr_Data,
};

pub fn castPtr(comptime T: type, ptr: anytype) T {
    return @ptrCast(@alignCast(ptr));
}

pub fn main() !void {
    var peb_ptr: ?*anyopaque = null;

    // 1. Получаем PEB
    asm volatile ("movq %%gs:0x60, %[peb_ptr]"
        : [peb_ptr] "=r" (peb_ptr),
    );

    if (peb_ptr) |peb| {
        const peb_struct = castPtr(*const Peb, peb);

        if (peb_struct.Ldr) |ldr_data| {
            const anchor_ptr = &ldr_data.InLoadOrderModuleList;

            if (ldr_data.InLoadOrderModuleList.Flink) |first_link| {
                var current_link: ?*List_entry = first_link;

                while (current_link) |link| {
                    const table_entry = castPtr(*const Ldr_table, link);

                    if (table_entry.BaseDllName.Buffer) |buf| {
                        const count = table_entry.BaseDllName.Length / 2;
                        const name_slice = buf[0..count];

                        const target_name = [_]u8{ 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l' };

                        if (name_slice.len == target_name.len) {
                            var is_match = true;

                            for (target_name, 0..) |target_char, i| {
                                const char_u8 = @as(u8, @truncate(name_slice[i]));
                                const dll_char = std.ascii.toLower(char_u8);

                                if (dll_char != target_char) {
                                    is_match = false;
                                    break;
                                }
                            }

                            if (is_match) {
                                std.debug.print("Found ntdll.dll at address: {x}\n", .{@intFromPtr(table_entry.DllBase)});
                                break;
                            }
                        }
                    }
                    current_link = table_entry.InLoadOrderLinks.Flink;

                    if (current_link == anchor_ptr) {
                        break;
                    }
                }
            }
        }
    } else {
        std.debug.print("Failed to retrieve PEB address.\n", .{});
    }
    _ = GetAsyncKeyState(VK_DELETE);
    Sleep(100);
    while (GetAsyncKeyState(VK_DELETE) >= 0) {
        Sleep(10);
    }
}
