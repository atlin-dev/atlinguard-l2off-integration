<p>
  <img src="AtlinGuard-logo-inline.svg" alt="AtlinGuard" width="300">
</p>

# Account/HWID history for L2OFF extenders

This guide is for the author of the L2OFF GameServer extender. `AtlinGuardHwid.dll` tells [AtlinGuard](https://atlinguard.com) which account logged in, on which connection, after the `AuthD` accepts the account. AtlinGuard already knows which machine is behind each connection, so it can record the account with its machine. It is optional and observation-only: it never decides a login, and the extender keeps its native behavior when the DLL is missing, not started or unable to reach the TenantServer.

The DLL is not an extender. It does not hook `L2Server.exe` and does not touch any packet, so it cannot conflict with the extender the server already runs; the game client sends nothing new to the GameServer.

## Binaries

`bin\x64` and `bin\x86` hold the ready `AtlinGuardHwid.dll` and its import library `AtlinGuardHwid.lib`. Use the architecture of your `L2Server.exe` and place the DLL beside it, or wherever the extender loads it from. The C runtime is linked statically, so no redistributable is needed.

Compiling it yourself is optional and needs Visual Studio 2017 version 15.7 or later. In the x64 or x86 Native Tools Command Prompt, from this folder:

```bat
cl /nologo /std:c++17 /EHsc /O2 /MT /DUNICODE /D_UNICODE /LD AtlinGuardHwid.cpp /link /DEF:AtlinGuardHwid.def winhttp.lib ws2_32.lib
```

## Integration

Include `AtlinGuardHwid.h`, a plain C interface usable from any MSVC version, including Visual Studio 2005 and 2008 projects. Link `AtlinGuardHwid.lib`, or load the DLL with `LoadLibrary` and resolve the five exports with `GetProcAddress` when the extender must keep working without it.

### 1. Start and stop

Call once during the extender's normal initialization, never from `DllMain`:

```c
int result = AtgHwid_Start(L"C:\\L2Server\\AtlinGuardHwid.ini");
/* ATG_HWID_STARTED, ATG_HWID_ALREADY_STARTED, ATG_HWID_CONFIG_INVALID or ATG_HWID_START_FAILED.
   Any failure only disables the history; continue normally. */
```

Call `AtgHwid_Stop()` during shutdown, also never from `DllMain`. Skipping it at process exit and freeing the library are both safe.

Copy `AtlinGuardHwid.ini` to the path you pass to `AtgHwid_Start` and fill in `TokenFile` and `Port` with the values from the server operator. The GameServer and the TenantServer must run on the same machine, because the DLL only talks to `127.0.0.1`. A relative path, for the INI file or for `TokenFile`, is resolved against the current directory of `L2Server.exe`. The token file holds one line of 32 to 256 ASCII characters, and the user account that runs the GameServer needs read access to it.

### 2. Report the authenticated login

Call this only after the native authentication accepted the account. In L2OFF the `AuthD` sends `AboutToPlay` with the session keys before the client connects; when the client's login packet arrives, `CDB::RequestLogin` compares its one-time key with them and, on a match, binds the account to the `CUserSocket`. Call the DLL on that success path, never at the start of the login packet handler, which also runs for logins that are refused. In the Interlude `L2Server.exe` this is the call to `0x53E130` at `0x53E94A`, where the account is at `CUserSocket+0x420` and the `SOCKET` at `CUserSocket+0x18`; the addresses change between chronicles and builds, so confirm them in yours.

```c
AtgHwid_ObserveAuthenticated(accountName, (UINT_PTR)nativeSocketHandle);
```

- `accountName`: the native account name (UTF-16).
- `nativeSocketHandle`: the `SOCKET` of this GameServer connection. The DLL reads its remote address and port. Players reach the GameServer through the AtlinGuard gateway, so they share its address and only the port identifies the connection.

The call only queues the observation and returns at once. Call it once per accepted login. An extender that already keeps the full remote address can call `AtgHwid_ObserveAuthenticatedPeer(account, "127.0.0.1:40123")` instead, never with only the IP.

### 3. Log the result

`AtgHwid_LastStatus()` returns the result of the last report: `ATG_HWID_STATUS_NONE` before the first one, the HTTP status of the TenantServer reply, or `ATG_HWID_STATUS_UNREACHABLE` when the TenantServer did not answer. `AtgHwid_Start` only checks the local configuration, so this is how the extender notices a wrong token or port. Log it when it changes, for example a few seconds after each login:

| Value | Meaning |
|---|---|
| `202` | accepted |
| `401` | the token does not match the TenantServer |
| `409` | the connection is unknown to the AtlinGuard gateway (wrong socket, or the player did not come through the gateway) |
| `400` | the TenantServer refused the account or the address |
| `503` | the history storage is unavailable on the TenantServer |
| `ATG_HWID_STATUS_UNREACHABLE` | nothing answered on the configured port |
