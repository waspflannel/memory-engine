#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "core/address_table/address_table.h"
#include "test/test.h"

#define TEMP_PATH_MAX MAX_PATH
#define FIXTURE_PATH_MAX (MAX_PATH + 64)

static volatile int watched_value = 10;

static int write_text_file(const wchar_t *path, const char *text)
{
    FILE *file = NULL;
    if (_wfopen_s(&file, path, L"wb") != 0 || !file) return 0;
    int ok = fputs(text, file) >= 0 && fclose(file) == 0;
    return ok;
}

static void check_rejected_file(AddrTable *table, const wchar_t *path,
                                const char *text, const char *message)
{
    check(write_text_file(path, text), "write malformed fixture");
    size_t prior_count = table->count;
    char prior_label[ADDR_ENTRY_LABEL_MAX];
    strcpy_s(prior_label, sizeof(prior_label), table->entries[0].label);
    check(addr_table_load(table, path) == ADDR_TABLE_IO_MALFORMED, message);
    check(table->count == prior_count && strcmp(table->entries[0].label, prior_label) == 0,
          "rejected load leaves table unchanged");
}

static void test_crud_and_target_lifecycle(Target *target)
{
    printf("--- address table CRUD and target lifecycle ---\n");
    AddrTable table;
    check(addr_table_init(&table, target), "table initializes");
    int index = addr_table_add(&table, "health", SCAN_TYPE_I32, (uintptr_t)&watched_value);
    check(index == 0, "fixed-width entry is added");
    check(addr_table_add(&table, "string", SCAN_TYPE_STRING, (uintptr_t)&watched_value) < 0,
          "variable-width string entry is rejected");
    check(addr_table_add(&table, "bad\"label", SCAN_TYPE_I32, (uintptr_t)&watched_value) < 0,
          "quoted label is rejected");
    check(addr_table_rename(&table, 0, "player health") == 0, "entry can be renamed");
    check(addr_table_rename(&table, 0, "bad\nlabel") != 0, "line-break label is rejected");

    watched_value = 10;
    check(addr_table_refresh(&table) == PLATFORM_OK, "refresh reads target value");
    check(table.entries[0].value_valid &&
          memcmp(table.entries[0].current_value, (const void *)&watched_value, sizeof(watched_value)) == 0,
          "refresh caches current bytes");

    int locked_value = 77;
    bool had_error = false;
    size_t error_index = 0;
    check(addr_table_lock(&table, 0, &locked_value) == 0, "entry locks while attached");
    addr_table_lock_write(&table, &had_error, &error_index);
    check(!had_error && watched_value == 77, "lock write updates target");
    watched_value = 12;
    addr_table_lock_write(&table, &had_error, &error_index);
    check(watched_value == 77, "repeated lock write restores target value");
    check(addr_table_unlock(&table, 0) == 0, "entry unlocks");
    watched_value = 13;
    addr_table_lock_write(&table, &had_error, &error_index);
    check(watched_value == 13, "unlock stops writes");

    check(addr_table_lock(&table, 0, &locked_value) == 0, "entry relocks for transition test");
    addr_table_set_target(&table, NULL);
    check(!table.entries[0].locked && !table.entries[0].value_valid && table.target == NULL,
          "detach disables locks and invalidates cached values");
    check(addr_table_refresh(&table) == PLATFORM_ERR_INVALID_PARAM,
          "detached refresh reports no live target");

    addr_table_set_target(&table, target);
    check(!table.entries[0].locked, "reattach never rearms an old lock");
    check(addr_table_remove(&table, 0) == 0 && table.count == 0, "entry is removed");
    addr_table_destroy(&table);
}

static void test_persistence(Target *target)
{
    printf("--- strict transactional persistence ---\n");
    wchar_t temp_path[TEMP_PATH_MAX];
    wchar_t valid_path[FIXTURE_PATH_MAX];
    wchar_t invalid_path[FIXTURE_PATH_MAX];
    DWORD temp_length = GetTempPathW(TEMP_PATH_MAX, temp_path);
    if (temp_length == 0 || temp_length >= TEMP_PATH_MAX ||
        swprintf_s(valid_path, FIXTURE_PATH_MAX, L"%saddress-table-%lu-\x03A9-valid.mft",
                   temp_path, (unsigned long)GetCurrentProcessId()) < 0 ||
        swprintf_s(invalid_path, FIXTURE_PATH_MAX, L"%saddress-table-%lu-invalid.mft",
                   temp_path, (unsigned long)GetCurrentProcessId()) < 0) {
        check(0, "create unique persistence fixture paths");
        return;
    }

    AddrTable table;
    check(addr_table_init(&table, target), "persistence table initializes");
    check(addr_table_add(&table, "sentinel", SCAN_TYPE_I32, (uintptr_t)&watched_value) == 0,
          "sentinel entry added");

    int locked_value = 91;
    check(addr_table_lock(&table, 0, &locked_value) == 0, "saved entry can be locked");
    watched_value = 20;
    check(addr_table_save(&table, valid_path) == ADDR_TABLE_IO_OK, "Unicode path saves successfully");
    check(addr_table_load(&table, valid_path) == ADDR_TABLE_IO_OK, "valid table loads successfully");
    check(table.count == 1 && !table.entries[0].locked, "persisted lock loads inert");
    bool had_error = false;
    size_t error_index = 0;
    addr_table_lock_write(&table, &had_error, &error_index);
    check(watched_value == 20, "loaded table performs no implicit write");
    check(addr_table_lock(&table, 0, &locked_value) == 0, "loaded entry requires explicit relock");
    addr_table_lock_write(&table, &had_error, &error_index);
    check(watched_value == 91, "explicit relock enables writes");

    check_rejected_file(&table, invalid_path,
        "# MemForge Address Table v1\nentry \"x\" nope 0x1234 0\n",
        "invalid type is rejected");
    check_rejected_file(&table, invalid_path,
        "# MemForge Address Table v1\nentry \"x\" i32\n",
        "missing address is rejected without over-read");
    check_rejected_file(&table, invalid_path,
        "# MemForge Address Table v1\nentry \"x\" i32 -1 0\n",
        "negative address is rejected");
    check_rejected_file(&table, invalid_path,
        "# MemForge Address Table v1\nentry \"x\" i32 0x0 0\n",
        "zero address is rejected");
    check_rejected_file(&table, invalid_path,
        "# MemForge Address Table v1\nentry \"x\" string 0x1234 0\n",
        "unsupported table type is rejected");
    check_rejected_file(&table, invalid_path,
        "# MemForge Address Table v1\nentry \"x\" i32 0x1234 2\n",
        "invalid lock flag is rejected");
    check_rejected_file(&table, invalid_path,
        "# MemForge Address Table v1\nentry \"x\" i32 0x1234 1 00\n",
        "short lock value is rejected");
    check_rejected_file(&table, invalid_path,
        "# MemForge Address Table v1\nentry \"x\" i32 0x1234 0 junk\n",
        "trailing junk is rejected");
    check_rejected_file(&table, invalid_path,
        "# MemForge Address Table v1\nentry \"x\" i32",
        "truncated final entry is rejected");

    FILE *overlong = NULL;
    check(_wfopen_s(&overlong, invalid_path, L"wb") == 0 && overlong, "open overlong fixture");
    if (overlong) {
        fputs("# MemForge Address Table v1\nentry \"", overlong);
        for (int i = 0; i < 2100; i++) fputc('a', overlong);
        fputs("\" i32 0x1234 0\n", overlong);
        fclose(overlong);
        check(addr_table_load(&table, invalid_path) == ADDR_TABLE_IO_MALFORMED,
              "overlong line is rejected");
        check(table.count == 1, "overlong load leaves table unchanged");
    }

    check(addr_table_load(&table, L"missing-directory\\missing.mft") == ADDR_TABLE_IO_OPEN_FAILED,
          "open failure is distinguished from malformed input");
    addr_table_destroy(&table);
    DeleteFileW(valid_path);
    DeleteFileW(invalid_path);
}

int main(void)
{
    Target target = {0};
    target.handle = GetCurrentProcess();
    target.pid = GetCurrentProcessId();
    test_crud_and_target_lifecycle(&target);
    test_persistence(&target);
    printf("\n%d failure(s)\n", failures);
    return failures ? 1 : 0;
}
