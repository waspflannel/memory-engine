#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <wchar.h>
#include "tui_internal.h"

/* The worker owns this session until its thread has been joined. The target
   handle remains borrowed: detach always cancels and joins before closing it. */
static struct {
    HANDLE thread;
    ScanSession session;
    atomic_bool cancel;
    PlatformError error;
    int next;
} scan_job;

static DWORD WINAPI run_scan(LPVOID unused);

int tui_scan_is_running(void)
{
    return scan_job.thread != NULL;
}

void tui_start_scan(const ScanValue *value, int next)
{
    if (tui_scan_is_running()) {
        tui_set_status(L"A scan is already running", TRUE);
        return;
    }
    if (!tui_state.attached || !tui_state.scanner_inited) {
        tui_set_status(L"No process attached", TRUE);
        return;
    }
    if (next && !tui_state.scanner.has_results) {
        tui_set_status(L"Run `scan <value>` first", TRUE);
        return;
    }

    scan_job.session = tui_state.scanner;
    scan_job.session.param = *value;
    atomic_init(&scan_job.cancel, false);
    scan_job.session.cancel_requested = &scan_job.cancel;
    scan_job.next = next;
    scan_job.thread = CreateThread(NULL, 0, run_scan, NULL, 0, NULL);
    if (!scan_job.thread) {
        /* No worker acquired ownership; the original session still owns it. */
        scan_job.session = (ScanSession){0};
        tui_set_status(L"Could not start scan worker", TRUE);
        return;
    }
    tui_state.scanner.results = (ScanResults){0};
    tui_state.scanner.has_results = 0;
    tui_set_status(L"Scanning...", FALSE);
}

void tui_poll_scan(void)
{
    if (!scan_job.thread || WaitForSingleObject(scan_job.thread, 0) != WAIT_OBJECT_0) return;
    CloseHandle(scan_job.thread);
    scan_job.thread = NULL;
    tui_state.scanner = scan_job.session;
    tui_state.scanner.cancel_requested = NULL;
    scan_job.session = (ScanSession){0};

    wchar_t message[192];
    if (scan_job.error != PLATFORM_OK) {
        swprintf_s(message, _countof(message), L"%s scan failed: %S",
                   scan_job.next ? L"Next" : L"First", process_error_string(scan_job.error));
    } else {
        const ScanResults *results = &tui_state.scanner.results;
        tui_state.scanner_selected_index = 0;
        swprintf_s(message, _countof(message), L"%s scan: %llu %s; %llu %s",
                   scan_job.next ? L"Next" : L"First", (unsigned long long)results->count,
                   scan_job.next ? L"survivors" : L"hits",
                   (unsigned long long)(scan_job.next ? results->unreadable_candidates : results->skipped_regions),
                   scan_job.next ? L"unreadable candidates removed" : L"volatile regions ignored");
    }
    tui_set_status(message, scan_job.error != PLATFORM_OK);
}

void tui_cancel_scan(void)
{
    if (!scan_job.thread) return;
    atomic_store(&scan_job.cancel, true);
    WaitForSingleObject(scan_job.thread, INFINITE);
    CloseHandle(scan_job.thread);
    scan_job.thread = NULL;
    scanner_session_destroy(&scan_job.session);
}

static DWORD WINAPI run_scan(LPVOID unused)
{
    (void)unused;
    scan_job.error = scan_job.next ? scanner_next_scan(&scan_job.session) :
                                   scanner_first_scan(&scan_job.session);
    return 0;
}
