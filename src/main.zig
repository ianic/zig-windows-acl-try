const std = @import("std");
const fs = std.fs;
const win = std.os.windows;
const api = @import("aclapi.zig");

pub fn main() !void {
    fs.cwd().deleteTree("tmp") catch {};
    try fs.cwd().makePath("tmp");
    const tmp = try fs.cwd().openDir("tmp", .{});

    var user = CurrentUser.init();
    defer user.deinit();

    var file = try createFile(tmp, "foo", .{}, 0o644);
    try showFileAcl(file);
    std.debug.print("foo effective access mask: {x}\n", .{try user.fileAccessMask(file)});
    file.close();

    file = try createFile(tmp, "bar", .{}, 0o751);
    try showFileAcl(file);
    std.debug.print("bar effective access mask: {x}\n", .{try user.fileAccessMask(file)});
    file.close();

    file = try createFile(tmp, "default", .{}, 0);
    try showFileAcl(file);
    std.debug.print("default effective access mask: {x}\n", .{try user.fileAccessMask(file)});
    file.close();
}

// Copied from std.fs.Dir.zig, added mode attribute.
// In lib/std/c/windows.zig:28 mode_t is declared as u0.
pub fn createFile(self: fs.Dir, sub_path: []const u8, flags: fs.File.CreateFlags, mode: u32) fs.File.OpenError!fs.File {
    const path_w = try std.os.windows.sliceToPrefixedFileW(self.fd, sub_path);
    return createFileW(self, path_w.span(), flags, mode);
}

// Copied from std.fs.Dir.zig, added mode attribute and few more lines
pub fn createFileW(self: fs.Dir, sub_path_w: []const u16, flags: fs.File.CreateFlags, mode: u32) fs.File.OpenError!fs.File {
    const w = std.os.windows;
    const read_flag = if (flags.read) @as(u32, w.GENERIC_READ) else 0;

    // added -------------------------------------------------
    var sd = ModeToAcl.init();
    defer sd.deinit();
    var sa: win.SECURITY_ATTRIBUTES = .{
        .nLength = 0, // not used in OpenFile
        .lpSecurityDescriptor = sd.securityDescriptor(mode) catch return error.Unexpected,
        .bInheritHandle = win.FALSE,
    };
    // ------------------------------------------------------

    const file: fs.File = .{
        .handle = try w.OpenFile(sub_path_w, .{
            .dir = self.fd,
            .access_mask = w.SYNCHRONIZE | w.GENERIC_WRITE | read_flag,
            .creation = if (flags.exclusive)
                @as(u32, w.FILE_CREATE)
            else if (flags.truncate)
                @as(u32, w.FILE_OVERWRITE_IF)
            else
                @as(u32, w.FILE_OPEN_IF),
            .sa = &sa, // ------------------------------------------------------
        }),
    };
    errdefer file.close();
    var io: w.IO_STATUS_BLOCK = undefined;
    const range_off: w.LARGE_INTEGER = 0;
    const range_len: w.LARGE_INTEGER = 1;
    const exclusive = switch (flags.lock) {
        .none => return file,
        .shared => false,
        .exclusive => true,
    };
    try w.LockFile(
        file.handle,
        null,
        null,
        null,
        &io,
        &range_off,
        &range_len,
        null,
        @intFromBool(flags.lock_nonblocking),
        @intFromBool(exclusive),
    );
    return file;
}

const CurrentUser = struct {
    token_buffer: [api.TOKEN_USER_MAX_SIZE]u8 align(@alignOf(api.TOKEN_USER)) = undefined,
    groups_buffer: [@sizeOf(api.DWORD) + @sizeOf(api.SID_AND_ATTRIBUTES) * 32]u8 align(@alignOf(api.TOKEN_GROUPS)) = undefined,
    groups_ptr: api.LPVOID = null,

    token: ?*api.TOKEN_USER = null,
    groups: ?*api.TOKEN_GROUPS = null,

    pub fn init() CurrentUser {
        return .{};
    }

    pub fn token(self: *CurrentUser) !api.TOKEN_USER {
        if (self.token == null) try self.getUser();
        return self.token.?;
    }

    pub fn sid(self: *CurrentUser) !api.PSID {
        if (self.token == null) try self.getUser();
        return self.token.?.User.Sid;
    }

    fn getUser(self: *CurrentUser) !void {
        var proc: api.HANDLE = null;
        var ok = api.OpenProcessToken(api.GetCurrentProcess(), api.TOKEN_ADJUST_PRIVILEGES | api.TOKEN_QUERY, &proc);
        if (ok == 0) return error.OpenProcessToken;

        var token_len: api.DWORD = 0;
        const p_token: api.LPVOID = @ptrCast(&self.token_buffer);
        ok = api.GetTokenInformation(proc, api.TokenUser, p_token, self.token_buffer.len, &token_len);
        if (ok == 0) return error.GetTokenInformation;

        self.token = @as(*api.TOKEN_USER, @ptrCast(@alignCast(p_token)));
    }

    pub fn groups(self: *CurrentUser) !void {
        if (self.groups == null) try self.getGroups();
        return self.groups.?;
    }

    pub fn defaultGroupSid(self: *CurrentUser) !?api.PSID {
        if (self.groups == null) try self.getGroups();
        const gps = self.groups.?;
        if (gps.GroupCount == 0) return null;
        return gps.Groups[0].Sid;
    }

    fn getGroups(self: *CurrentUser) !void {
        var proc: api.HANDLE = null;
        var ok = api.OpenProcessToken(api.GetCurrentProcess(), api.TOKEN_ADJUST_PRIVILEGES | api.TOKEN_QUERY, &proc);
        if (ok == 0) return error.OpenProcessToken;

        var token_len: api.DWORD = 0;
        const p_token: api.LPVOID = @ptrCast(&self.groups_buffer);
        ok = api.GetTokenInformation(proc, api.TokenGroups, p_token, self.groups_buffer.len, &token_len);
        if (ok != 0) {
            self.groups = @as(*api.TOKEN_GROUPS, @ptrCast(@alignCast(&self.groups_buffer)));
            return;
        }
        if (api.GetLastError() != api.ERROR_INSUFFICIENT_BUFFER)
            return error.GetTokenInformation;

        // If groups_buffer is not enough allocate new big enough buffer pointed by groups_ptr
        self.groups_ptr = api.LocalAlloc(api.LPTR, token_len);
        ok = api.GetTokenInformation(proc, api.TokenGroups, self.groups_ptr, token_len, &token_len);
        if (ok == 0) return error.GetTokenInformation;

        self.groups = @as(*api.TOKEN_GROUPS, @ptrCast(@alignCast(self.groups_ptr)));
    }

    pub fn fileAccessMask(self: *CurrentUser, file: fs.File) !api.ACCESS_MASK {
        const object_type: api.SE_OBJECT_TYPE = api.SE_FILE_OBJECT;
        const security_info: api.SECURITY_INFORMATION = api.DACL_SECURITY_INFORMATION;
        var psd: api.PSECURITY_DESCRIPTOR = undefined;
        var acl: api.PACL = null;

        var errno = api.GetSecurityInfo(file.handle, object_type, security_info, null, null, &acl, null, &psd);
        if (errno != 0) return error.GetSecurityInfo;
        defer _ = api.LocalFree(psd);

        const ok = api.IsValidAcl(acl);
        if (ok == 0) return error.IsValidAcl;

        var trustee: api.TRUSTEE_A = undefined;
        api.BuildTrusteeWithSidA(&trustee, try self.sid());

        var access_mask: api.ACCESS_MASK = 0;
        errno = api.GetEffectiveRightsFromAclA(acl, &trustee, &access_mask);
        if (errno != 0) return error.GetEffectiveRightsFromAclA;

        return access_mask;
    }

    pub fn deinit(self: *CurrentUser) void {
        if (self.groups_ptr) |ptr| {
            _ = api.LocalFree(ptr);
        }
    }
};

const ModeToAcl = struct {
    buffer: [api.SECURITY_DESCRIPTOR_MIN_LENGTH]u8 align(8) = undefined,
    acl: api.PACL = null,
    security_descriptor: ?*anyopaque = null,

    pub fn init() ModeToAcl {
        return .{};
    }

    // Returns security descriptor with ACL generated from posix file access mode.
    pub fn securityDescriptor(self: *ModeToAcl, mode: u32) !?*anyopaque {
        if (mode == 0)
            return null; // preserve default behavior

        if (self.security_descriptor != null)
            self.deinit();

        var user = CurrentUser.init();
        defer user.deinit();

        // Create ACL entries
        var entries: [3]api.EXPLICIT_ACCESS_A = undefined;
        var entries_len: c_ulong = 3;

        entries[0] = aclUserEntry(mode, try user.sid());
        if (try user.defaultGroupSid()) |group_sid| {
            entries[1] = aclGroupEntry(mode, group_sid);
        } else {
            entries_len = 2;
        }
        var everyone_sid = try everyoneSid();
        entries[entries_len - 1] = aclEveryoneEntry(mode, &everyone_sid);

        // Create ACL from entries
        var acl: api.PACL = null;
        const errno = api.SetEntriesInAclA(entries_len, &entries[0], null, &acl);
        if (errno != 0) return error.SetEntriesInAclA;
        errdefer _ = api.LocalFree(acl);

        // Create security descriptor for ACL
        const psd: api.HLOCAL = @ptrCast(&self.buffer);
        var ok = api.InitializeSecurityDescriptor(psd, api.SECURITY_DESCRIPTOR_REVISION);
        if (ok == 0) return error.InitializeSecurityDescriptor;
        ok = api.SetSecurityDescriptorDacl(psd, api.TRUE, acl, api.FALSE);
        if (ok == 0) return error.SetSecurityDescriptorDacl;

        self.acl = acl;
        self.security_descriptor = psd;
        return psd;
    }

    // Create well known sid for everyone group
    fn everyoneSid() !api.SID {
        var sid: api.SID = undefined;
        var sid_len: c_ulong = @sizeOf(api.SID);
        const ok = api.CreateWellKnownSid(api.WinWorldSid, null, &sid, &sid_len);
        if (ok == 0) return error.CreateWelKnownSid;
        return sid;
    }

    fn aclUserEntry(mode: u32, sid: api.PSID) api.EXPLICIT_ACCESS_A {
        return aclEntry(mode, std.os.linux.S.IRWXU, sid);
    }

    fn aclGroupEntry(mode: u32, sid: api.PSID) api.EXPLICIT_ACCESS_A {
        return aclEntry(mode, std.os.linux.S.IRWXG, sid);
    }

    fn aclEveryoneEntry(mode: u32, sid: api.PSID) api.EXPLICIT_ACCESS_A {
        return aclEntry(mode, std.os.linux.S.IRWXO, sid);
    }

    // Create ACL entry for file mode
    fn aclEntry(mode: u32, mask: u32, sid: api.PSID) api.EXPLICIT_ACCESS_A {
        const none: api.DWORD = 0;
        const bits = (mode & mask) >> @as(u5, @intCast(@ctz(mask)));
        var entry = api.EXPLICIT_ACCESS_A{
            .grfAccessMode = api.GRANT_ACCESS,
            .grfAccessPermissions = win.SYNCHRONIZE |
                (if (bits & 4 != 0) win.GENERIC_READ else none) |
                (if (bits & 2 != 0) win.GENERIC_WRITE else none) |
                (if (bits & 1 != 0) win.GENERIC_EXECUTE else none),
            .grfInheritance = api.NO_INHERITANCE,
        };
        api.BuildTrusteeWithSidA(&entry.Trustee, sid);
        return entry;
    }

    pub fn deinit(self: *ModeToAcl) void {
        if (self.acl != null)
            _ = api.LocalFree(self.acl);
        self.acl = null;
        self.security_descriptor = null;
    }
};

test "aclEntry" {
    const mode: u32 = 0o643;
    try std.testing.expectEqual(6, (mode & std.os.linux.S.IRWXU) >> 6);
    try std.testing.expectEqual(4, (mode & std.os.linux.S.IRWXG) >> 3);
    try std.testing.expectEqual(3, (mode & std.os.linux.S.IRWXO));

    var mask: u32 = std.os.linux.S.IRWXU;
    try std.testing.expectEqual(6, (mode & mask) >> @as(u5, @intCast(@ctz(mask))));
    mask = std.os.linux.S.IRWXG;
    try std.testing.expectEqual(4, (mode & mask) >> @as(u5, @intCast(@ctz(mask))));
    mask = std.os.linux.S.IRWXO;
    try std.testing.expectEqual(3, (mode & mask) >> @as(u5, @intCast(@ctz(mask))));
}

pub fn showFileAcl(file: fs.File) !void {
    const object_type: api.SE_OBJECT_TYPE = api.SE_FILE_OBJECT;
    const security_info: api.SECURITY_INFORMATION = api.DACL_SECURITY_INFORMATION;
    var psd: api.PSECURITY_DESCRIPTOR = undefined;
    var acl: api.PACL = null;

    // https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo
    const errno = api.GetSecurityInfo(file.handle, object_type, security_info, null, null, &acl, null, &psd);
    if (errno != 0) return error.GetSecurityInfo;

    try showAcl(acl);
    _ = api.LocalFree(psd);
}

fn showAcl(acl: api.PACL) !void {
    var ok = api.IsValidAcl(acl);
    if (ok == 0) return error.IsValidAcl;

    // number of entries
    const ace_count: usize = @intCast(acl.*.AceCount);

    for (0..ace_count) |i| {
        var ptr: api.LPVOID = null;

        ok = api.GetAce(acl, @intCast(i), &ptr);
        if (ok == 0) return error.GetAce;

        // First get header
        // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-ace_header
        const ace_header: *api.ACE_HEADER = @ptrCast(@alignCast(ptr));
        const inherited = ace_header.AceFlags & api.INHERITED_ACE != 0;

        // Show only access allowed
        if (ace_header.AceType == api.ACCESS_ALLOWED_ACE_TYPE or
            ace_header.AceType == api.ACCESS_DENIED_ACE_TYPE)
        {
            // We can now cast to specific ace type
            const ace: *api.ACCESS_ALLOWED_ACE = @ptrCast(@alignCast(ptr));
            // Read execute bit
            const file_execute = ace.Mask & api.FILE_EXECUTE != 0;

            // Read domain/name from sid
            // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupaccountsida
            var name: [4096]u8 = undefined;
            var name_chars: c_ulong = name.len;
            var domain: [4096]u8 = undefined;
            var domain_chars: c_ulong = domain.len;
            var peUse: api.SID_NAME_USE = 0;
            ok = api.LookupAccountSidA(null, &ace.SidStart, &name, &name_chars, &domain, &domain_chars, &peUse);
            if (ok == 0) return error.LookupAccountSidA;

            if (ace_header.AceType == api.ACCESS_ALLOWED_ACE_TYPE)
                std.debug.print("  ALLOW ", .{})
            else
                std.debug.print("  DENY  ", .{});

            std.debug.print(
                "inherited: {}, access_mask: {x:0>6} {b:0>24}, file_execute: {:<5}, sid: {s}/{s}\n",
                .{
                    inherited,
                    ace.Mask,
                    ace.Mask,
                    file_execute,
                    domain[0..domain_chars],
                    name[0..name_chars],
                },
            );
        }
    }
}

// Mapping access mask to generic rights.
// ref: https://helgeklein.com/blog/how-to-map-generic-rights-to-standard-and-specific-rights/
//              Type Name All        Execute    Read       Write
//-----------------------+----------+----------+----------+----------
//                   File 0x001F01FF 0x001200A0 0x00120089 0x00120116
