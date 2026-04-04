/**
 * FFI Signature Verification Tests — post-fix
 *
 * Verifies that the corrected FFI signatures work correctly.
 * Tests functions whose FFI types were changed during the audit.
 */
import Advapi32, { HKEY_LOCAL_MACHINE } from '../index';

let passed = 0;
let failed = 0;

function assert(condition: boolean, name: string) {
  if (condition) {
    console.log(`  PASS: ${name}`);
    passed++;
  } else {
    console.log(`  FAIL: ${name}`);
    failed++;
  }
}

// ============================================================
// TEST 1: LookupPrivilegeValueW (arg[0] was u64, now ptr)
// lpSystemName is LPCWSTR — null means local system
// ============================================================
console.log('\n=== LookupPrivilegeValueW (arg[0] fixed: u64 → ptr) ===');
const luid = Buffer.alloc(8);
const privResult = Advapi32.LookupPrivilegeValueW(
  null as any, // nullable LPCWSTR — local system
  Buffer.from('SeShutdownPrivilege\0', 'utf16le').ptr,
  luid.ptr,
);
assert(privResult !== 0, 'returns TRUE for SeShutdownPrivilege with null system name');
assert(luid.readBigInt64LE(0) !== 0n, `LUID is non-zero (${luid.readBigInt64LE(0)})`);

// ============================================================
// TEST 2: LookupPrivilegeNameW (arg[0] was u64, now ptr)
// ============================================================
console.log('\n=== LookupPrivilegeNameW (arg[0] fixed: u64 → ptr) ===');
const nameLen = new Uint32Array([256]);
const nameBuf = new Uint16Array(256);
const lookupResult = Advapi32.LookupPrivilegeNameW(
  null as any, // nullable LPCWSTR
  luid.ptr,
  nameBuf.ptr,
  nameLen.ptr,
);
assert(lookupResult !== 0, 'returns TRUE for LUID lookup');
const privName = String.fromCharCode(...nameBuf.subarray(0, nameLen[0]!));
assert(privName === 'SeShutdownPrivilege', `privilege name = "${privName}"`);

// ============================================================
// TEST 3: LookupAccountNameW (arg[0] was u64, now ptr)
// ============================================================
console.log('\n=== LookupAccountNameW (arg[0] fixed: u64 → ptr) ===');
// First get the current username
const userNameSize = new Uint32Array([256]);
const userNameBuf = new Uint16Array(256);
Advapi32.GetUserNameW(userNameBuf.ptr, userNameSize.ptr);
const username = String.fromCharCode(...userNameBuf.subarray(0, userNameSize[0]! - 1));

const sidBuf = Buffer.alloc(68); // MAX SID
const sidLen = new Uint32Array([68]);
const domBuf = new Uint16Array(256);
const domLen = new Uint32Array([256]);
const sidUse = new Uint32Array(1);
const lookupAcct = Advapi32.LookupAccountNameW(
  null as any, // nullable LPCWSTR — local system
  Buffer.from(`${username}\0`, 'utf16le').ptr,
  sidBuf.ptr,
  sidLen.ptr,
  domBuf.ptr,
  domLen.ptr,
  sidUse.ptr,
);
assert(lookupAcct !== 0, `found SID for user "${username}"`);
assert(sidLen[0]! > 0, `SID length = ${sidLen[0]}`);

// ============================================================
// TEST 4: LookupAccountSidW (arg[0] was u64, now ptr)
// ============================================================
console.log('\n=== LookupAccountSidW (arg[0] fixed: u64 → ptr) ===');
const acctNameBuf = new Uint16Array(256);
const acctNameLen = new Uint32Array([256]);
const acctDomBuf = new Uint16Array(256);
const acctDomLen = new Uint32Array([256]);
const acctSidUse = new Uint32Array(1);
const lookupSid = Advapi32.LookupAccountSidW(
  null as any, // nullable LPCWSTR — local system
  sidBuf.ptr,
  acctNameBuf.ptr,
  acctNameLen.ptr,
  acctDomBuf.ptr,
  acctDomLen.ptr,
  acctSidUse.ptr,
);
assert(lookupSid !== 0, 'reverse lookup from SID succeeded');
const resolvedName = String.fromCharCode(...acctNameBuf.subarray(0, acctNameLen[0]!));
assert(resolvedName === username, `resolved name "${resolvedName}" matches "${username}"`);

// ============================================================
// TEST 5: OpenSCManagerW (args[0,1] were u64, now ptr)
// ============================================================
console.log('\n=== OpenSCManagerW (args[0,1] fixed: u64 → ptr) ===');
const SC_MANAGER_CONNECT = 0x0001;
const hSCManager = Advapi32.OpenSCManagerW(
  null as any, // nullable LPCWSTR — local machine
  null as any, // nullable LPCWSTR — SERVICES_ACTIVE_DATABASE
  SC_MANAGER_CONNECT,
);
assert(hSCManager !== 0n, `SC manager handle = 0x${hSCManager.toString(16)}`);
if (hSCManager !== 0n) {
  Advapi32.CloseServiceHandle(hSCManager);
}

// ============================================================
// TEST 6: OpenEventLogW (arg[0] was u64, now ptr)
// ============================================================
console.log('\n=== OpenEventLogW (arg[0] fixed: u64 → ptr) ===');
const hEventLog = Advapi32.OpenEventLogW(
  null as any, // nullable LPCWSTR — local machine
  Buffer.from('Application\0', 'utf16le').ptr,
);
assert(hEventLog !== 0n, `event log handle = 0x${hEventLog.toString(16)}`);
if (hEventLog !== 0n) {
  Advapi32.CloseEventLog(hEventLog);
}

// ============================================================
// TEST 7: RegisterEventSourceW (arg[0] was u64, now ptr)
// ============================================================
console.log('\n=== RegisterEventSourceW (arg[0] fixed: u64 → ptr) ===');
const hEvtSrc = Advapi32.RegisterEventSourceW(
  null as any, // nullable LPCWSTR — local machine
  Buffer.from('Application\0', 'utf16le').ptr,
);
assert(hEvtSrc !== 0n, `event source handle = 0x${hEvtSrc.toString(16)}`);
if (hEvtSrc !== 0n) {
  Advapi32.DeregisterEventSource(hEvtSrc);
}

// ============================================================
// TEST 8: RegEnumValueW (arg[4] was u64, now ptr — lpReserved)
// Open a key, enumerate first value
// ============================================================
console.log('\n=== RegEnumValueW (arg[4] fixed: u64 → ptr) ===');
const hkeyOut = new BigUint64Array(1);
const openStatus = Advapi32.RegOpenKeyExW(
  HKEY_LOCAL_MACHINE,
  Buffer.from('SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\0', 'utf16le').ptr,
  0,
  0x0002_0019, // KEY_READ
  hkeyOut.ptr,
);
assert(openStatus === 0, `RegOpenKeyExW succeeded (status=${openStatus})`);

if (openStatus === 0) {
  const hkey = hkeyOut[0]!;
  const valName = new Uint16Array(256);
  const valNameLen = new Uint32Array([256]);
  const valType = new Uint32Array(1);
  const valData = Buffer.alloc(1024);
  const valDataLen = new Uint32Array([1024]);

  const enumStatus = Advapi32.RegEnumValueW(
    hkey,
    0,
    valName.ptr,
    valNameLen.ptr,
    null as any, // lpReserved — was u64, now ptr, should accept null
    valType.ptr,
    valData.ptr,
    valDataLen.ptr,
  );
  assert(enumStatus === 0, `RegEnumValueW first value (status=${enumStatus})`);
  if (enumStatus === 0) {
    const name = String.fromCharCode(...valName.subarray(0, valNameLen[0]!));
    assert(name.length > 0, `first value name = "${name}"`);
  }

  Advapi32.RegCloseKey(hkey);
}

// ============================================================
// TEST 9: AdjustTokenPrivileges (args[4,5] were u64, now ptr)
// ============================================================
console.log('\n=== AdjustTokenPrivileges (args[4,5] fixed: u64 → ptr) ===');
{
  // Open process token
  const hProcess = (await import('bun:ffi')).dlopen('kernel32.dll', {
    GetCurrentProcess: { args: [], returns: (await import('bun:ffi')).FFIType.u64 },
  }).symbols.GetCurrentProcess();

  const tokenHandle = new BigUint64Array(1);
  const TOKEN_ADJUST_PRIVILEGES = 0x0020;
  const TOKEN_QUERY = 0x0008;
  const openToken = Advapi32.OpenProcessToken(
    hProcess as bigint,
    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
    tokenHandle.ptr,
  );
  assert(openToken !== 0, 'OpenProcessToken succeeded');

  if (openToken !== 0) {
    const token = tokenHandle[0]!;
    // Call with DisableAllPrivileges = TRUE, no NewState, PreviousState=null, ReturnLength=null
    const adjustResult = Advapi32.AdjustTokenPrivileges(
      token,
      0, // FALSE — don't disable all
      null as any, // no new state
      0,
      null as any, // PreviousState (was u64, now ptr) — null
      null as any, // ReturnLength (was u64, now ptr) — null
    );
    // With no NewState, returns 0 (ERROR_INVALID_PARAMETER) — the key test is no crash
    assert(typeof adjustResult === 'number', `AdjustTokenPrivileges returned ${adjustResult} (no crash)`);

    // Clean up
    const { dlopen: dl2, FFIType: FT2 } = await import('bun:ffi');
    dl2('kernel32.dll', { CloseHandle: { args: [FT2.u64], returns: FT2.i32 } }).symbols.CloseHandle(token);
  }
}

// ============================================================
// TEST 10: SetSecurityDescriptorDacl (arg[2] was u64, now ptr — pDacl)
// ============================================================
console.log('\n=== SetSecurityDescriptorDacl (arg[2] fixed: u64 → ptr) ===');
{
  const sd = Buffer.alloc(40); // SECURITY_DESCRIPTOR_MIN_LENGTH = 20..40
  const initResult = Advapi32.InitializeSecurityDescriptor(sd.ptr, 1);
  assert(initResult !== 0, 'InitializeSecurityDescriptor succeeded');

  // Set a NULL DACL (allow all access)
  const setResult = Advapi32.SetSecurityDescriptorDacl(
    sd.ptr,
    1, // bDaclPresent = TRUE
    null as any, // pDacl = NULL (was u64, now ptr)
    0, // bDaclDefaulted = FALSE
  );
  assert(setResult !== 0, 'SetSecurityDescriptorDacl with null DACL succeeded');
}

// ============================================================
// TEST 11: RegConnectRegistryW (arg[0] was u64, now ptr)
// ============================================================
console.log('\n=== RegConnectRegistryW (arg[0] fixed: u64 → ptr) ===');
{
  const hkeyRemote = new BigUint64Array(1);
  const connStatus = Advapi32.RegConnectRegistryW(
    null as any, // local machine — nullable LPCWSTR
    HKEY_LOCAL_MACHINE,
    hkeyRemote.ptr,
  );
  assert(connStatus === 0, `RegConnectRegistryW to local machine (status=${connStatus})`);
  if (connStatus === 0) {
    Advapi32.RegCloseKey(hkeyRemote[0]!);
  }
}

// ============================================================
// TEST 12: CredEnumerateW (arg[0] was u64, now ptr)
// ============================================================
console.log('\n=== CredEnumerateW (arg[0] fixed: u64 → ptr) ===');
{
  const count = new Uint32Array(1);
  const credsPtr = new BigUint64Array(1);
  // Enumerate with null filter — may return ERROR_NOT_FOUND (1168) if no creds
  const credResult = Advapi32.CredEnumerateW(
    null as any, // Filter — nullable LPCWSTR
    0,
    count.ptr,
    credsPtr.ptr,
  );
  // Either succeeds or returns 0 with ERROR_NOT_FOUND
  assert(typeof credResult === 'number', `CredEnumerateW returned ${credResult} (no crash)`);
}

// ============================================================
// TEST 13: LookupPrivilegeDisplayNameW (arg[0] was u64, now ptr)
// ============================================================
console.log('\n=== LookupPrivilegeDisplayNameW (arg[0] fixed: u64 → ptr) ===');
{
  const dispBuf = new Uint16Array(256);
  const dispLen = new Uint32Array([256]);
  const langId = new Uint32Array(1);
  const dispResult = Advapi32.LookupPrivilegeDisplayNameW(
    null as any, // nullable LPCWSTR — local system
    Buffer.from('SeShutdownPrivilege\0', 'utf16le').ptr,
    dispBuf.ptr,
    dispLen.ptr,
    langId.ptr,
  );
  assert(dispResult !== 0, 'LookupPrivilegeDisplayNameW succeeded');
  if (dispResult !== 0) {
    const displayName = String.fromCharCode(...dispBuf.subarray(0, dispLen[0]!));
    assert(displayName.length > 0, `display name = "${displayName}"`);
  }
}

// ============================================================
// TEST 14: AbortSystemShutdownW (arg[0] was u64, now ptr)
// We call with local machine — no shutdown is pending so it just returns FALSE
// ============================================================
console.log('\n=== AbortSystemShutdownW (arg[0] fixed: u64 → ptr) ===');
{
  const abortResult = Advapi32.AbortSystemShutdownW(null as any);
  // Returns FALSE (0) if no shutdown is in progress — that's expected
  assert(typeof abortResult === 'number', `AbortSystemShutdownW returned ${abortResult} (no crash)`);
}

// ============================================================
// SUMMARY
// ============================================================
console.log(`\n${'='.repeat(50)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
