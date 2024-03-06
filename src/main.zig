const std = @import("std");
const fs = std.fs;
const win = std.os.windows;
const api = @import("aclapi.zig");

pub fn main() !void {
    try fs.cwd().makePath("tmp");
    var root = try fs.cwd().openDir("tmp", .{});
    root.deleteFile("foo") catch |err| {
        if (err != error.FileNotFound) return err;
    };

    var file = try root.createFile("foo", .{ .truncate = true });
    defer file.close();

    std.debug.print("tmp/foo\n", .{});
    try showFileAcl(file);

    try addAclEntry("tmp\\foo");
    std.debug.print("tmp/foo with one more entry\n", .{});
    try showFileAcl(file);
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
        if (ace_header.AceType == api.ACCESS_ALLOWED_ACE_TYPE) {
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

            std.debug.print(
                "\t inherited: {}, access_mask: {x} {b}, file_execute: {}, sid: {s}/{s}\n",
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

// Can't use file.handle here getting ERROR_ACCESS_DENIED on SetSecurityInfo
// probably handle is opened with insufficient right to set permission.
// Right required to set is WRITE_DAC
fn addAclEntry(file_name: []const u8) !void {
    var c_file_name = try std.posix.toPosixPath(file_name);

    // Read current acl for file
    const object_type: api.SE_OBJECT_TYPE = api.SE_FILE_OBJECT;
    var security_info: api.SECURITY_INFORMATION = api.DACL_SECURITY_INFORMATION;
    var psd: api.PSECURITY_DESCRIPTOR = undefined;
    var acl: api.PACL = null;
    var errno = api.GetNamedSecurityInfoA(&c_file_name, object_type, security_info, null, null, &acl, null, &psd);
    if (errno != 0) return error.GetSecurityInfo;

    var ok = api.IsValidAcl(acl);
    if (ok == 0) return error.IsValidAcl;

    // Get sid for Everyone (1)
    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-well_known_sid_type
    var sid: api.SID = undefined;
    var sid_len: c_ulong = @sizeOf(api.SID);
    ok = api.CreateWellKnownSid(1, null, &sid, &sid_len);
    if (ok == 0) return error.CreateWelKnownSid;

    // Create new entry
    var new_entry: api.EXPLICIT_ACCESS_A = .{
        .grfAccessMode = api.GRANT_ACCESS,
        .grfAccessPermissions = win.SYNCHRONIZE | win.FILE_EXECUTE, // only file execute
        .grfInheritance = api.NO_INHERITANCE,
    };
    api.BuildTrusteeWithSidA(&new_entry.Trustee, &sid);

    // Add new entry to the existing acl
    var new_acl: api.PACL = null;
    errno = api.SetEntriesInAclA(1, &new_entry, acl, &new_acl);
    if (errno != 0) return error.SetEntriesInAclA;

    // Apply new acl to the file
    // https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setnamedsecurityinfoa
    security_info = api.DACL_SECURITY_INFORMATION | api.UNPROTECTED_DACL_SECURITY_INFORMATION;
    errno = api.SetNamedSecurityInfoA(&c_file_name, object_type, security_info, null, null, new_acl, null);
    if (errno != 0) return error.SetSecurityInfo;

    _ = api.LocalFree(psd);
    _ = api.LocalFree(new_acl);
}
