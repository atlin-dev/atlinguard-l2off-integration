/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 AtlinGuard
 *
 * AtlinGuard account/HWID history for L2OFF extenders. See README.md.
 */
#ifndef ATLINGUARD_HWID_H
#define ATLINGUARD_HWID_H

#include <stddef.h>
#include <basetsd.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ATLINGUARD_HWID_BUILD
#define ATG_HWID_API __declspec(dllexport)
#else
#define ATG_HWID_API __declspec(dllimport)
#endif

#define ATG_HWID_CALL __cdecl

/* AtgHwid_Start results. */
#define ATG_HWID_STARTED 0
#define ATG_HWID_ALREADY_STARTED 1
#define ATG_HWID_CONFIG_INVALID (-1)
#define ATG_HWID_START_FAILED (-2)

/* AtgHwid_LastStatus results besides an HTTP status (202 means accepted). */
#define ATG_HWID_STATUS_NONE 0
#define ATG_HWID_STATUS_UNREACHABLE (-1)

/* Reads the INI file and starts the reporter. Never call it from DllMain. */
ATG_HWID_API int ATG_HWID_CALL AtgHwid_Start(const wchar_t* configPath);

/* Stops the reporter and drops pending reports. Never call it from DllMain. */
ATG_HWID_API void ATG_HWID_CALL AtgHwid_Stop(void);

/* Queues one accepted login: the native account name (UTF-16, at most 64 UTF-8 bytes) and the SOCKET of its connection. */
ATG_HWID_API void ATG_HWID_CALL AtgHwid_ObserveAuthenticated(const wchar_t* account, UINT_PTR socketHandle);

/* Same, with the remote address as "a.b.c.d:port" or "[ipv6]:port". */
ATG_HWID_API void ATG_HWID_CALL AtgHwid_ObserveAuthenticatedPeer(const wchar_t* account, const char* gatewayPeer);

/* Result of the last report: ATG_HWID_STATUS_NONE, an HTTP status or ATG_HWID_STATUS_UNREACHABLE. */
ATG_HWID_API int ATG_HWID_CALL AtgHwid_LastStatus(void);

#ifdef __cplusplus
}
#endif

#endif /* ATLINGUARD_HWID_H */
