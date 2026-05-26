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

const Dos_header = extern struct {
    e_magic: u16,
    Padding: [58]u8,
    e_lfanew: u32,
};

const Nt_header = extern struct {
    Signature: u32,
    Machine: u16,
    NumberOfSections: u16,
    Padding: [12]u8,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
};

const Section_header = extern struct {
    Name: [8]u8,
    VirtualSize: u32,
    VirtualAddress: u32,
    SizeOfRawData: u32,
    PointerToRawData: u32,
    Padding: [16]u8,
};

pub fn castPtr(comptime T: type, ptr: anytype) T {
    return @ptrCast(@alignCast(ptr));
}

pub fn main() !void {
    Sleep(10000);
    var peb_ptr: ?*anyopaque = null;
    var dll_address: ?*anyopaque = null;

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
                                dll_address = table_entry.DllBase;
                                std.debug.print("Found ntdll.dll at address: {x}\n", .{@intFromPtr(dll_address)});
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

    var buffer: [0x40]u8 = undefined;

    const file = try std.fs.openFileAbsolute("C:\\Windows\\System32\\ntdll.dll", .{});
    _ = try file.read(&buffer);

    const dos = castPtr(*const Dos_header, &buffer);

    if (dos.e_magic == 0x5A4D) { // 'MZ'
        std.debug.print("Jackpot!\n", .{});
    }

    const e_lfanew = dos.e_lfanew;
    std.debug.print("e_lfanew: {x}\n", .{e_lfanew});

    _ = try file.seekTo(e_lfanew);

    var nt_buffer: [0x18]u8 = undefined;
    _ = try file.read(&nt_buffer);
    const nt = castPtr(*const Nt_header, &nt_buffer);

    if (nt.Signature == 0x4550) { // 'PE\0\0'
        std.debug.print("PE header found!\n", .{});
        std.debug.print("Number of sections: {d}\n", .{nt.NumberOfSections});
        std.debug.print("Size of optional header: {d}\n", .{nt.SizeOfOptionalHeader});
    }

    var sec_buffer: [40]u8 = undefined;

    const FirstSectionOffset = e_lfanew + @sizeOf(Nt_header) + nt.SizeOfOptionalHeader;
    _ = try file.seekTo(FirstSectionOffset);

    var text_va: u32 = 0;
    var text_size: u32 = 0;
    var text_raw: u32 = 0;

    for (0..nt.NumberOfSections) |i| {
        _ = i;
        _ = try file.read(&sec_buffer);
        const section = castPtr(*const Section_header, &sec_buffer);
        if (std.mem.eql(u8, &section.Name, ".text\x00\x00\x00")) {
            text_va = section.VirtualAddress;
            text_size = @min(section.VirtualSize, section.SizeOfRawData);
            text_raw = section.PointerToRawData;
            std.debug.print(".text section found!\n", .{});
            std.debug.print("Virtual Address: {x}\n", .{section.VirtualAddress});
            std.debug.print("Size of Raw Data: {x}\n", .{section.SizeOfRawData});
        }
    }

    const text_in_memory_ptr = @intFromPtr(dll_address.?) + text_va;
    std.debug.print(".text section loaded at: {x}\n", .{text_in_memory_ptr});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    const disk_text = try allocator.alloc(u8, text_size);
    defer allocator.free(disk_text);

    try file.seekTo(text_raw);
    var bytes_read: usize = 0;
    while (bytes_read < text_size) {
        const n = try file.read(disk_text[bytes_read..]);
        if (n == 0) break;
        bytes_read += n;
    }

    const mem_ptr = @as([*]const u8, @ptrFromInt(text_in_memory_ptr));
    const mem_text = mem_ptr[0..text_size];
    const page_size = 4096;
    if (@intFromPtr(mem_ptr) % page_size != 0) {
        std.debug.print("Warning: Start address is not aligned to page boundary\n", .{});
    }

    std.debug.print("\nScanning for hooks...\n", .{});

    var hooks_found: u32 = 0;
    var i: usize = 0;
    while (i < text_size) : (i += 1) {
        if (disk_text[i] != mem_text[i]) {
            const modified_address = text_in_memory_ptr + i;

            std.debug.print("Hook detected at address: 0x{x} (Offset: 0x{x})\n", .{ modified_address, i });
            std.debug.print("  -> Expected (Disk): 0x{x:0>2}\n", .{disk_text[i]});
            std.debug.print("  -> Actual (Mem):  0x{x:0>2}\n", .{mem_text[i]});

            hooks_found += 1;

            if (hooks_found >= 15) {
                std.debug.print("Too many differences found. Stopping output to save console.\n", .{});
                break;
            }
        }
    }

    std.debug.print("\n=====================================\n", .{});
    std.debug.print("Scanning complete. Total hooks detected: {d}\n", .{hooks_found});
    std.debug.print("=====================================\n", .{});

    if (hooks_found == 0) {
        std.debug.print("System state: CLEAN.\n", .{});
    } else {
        std.debug.print("System state: COMPROMISED!\n", .{});
    }

    _ = GetAsyncKeyState(VK_DELETE);
    Sleep(100);
    while (GetAsyncKeyState(VK_DELETE) >= 0) {
        Sleep(10);
    }
}
