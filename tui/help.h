#ifndef HELP_H
#define HELP_H

#include <wchar.h>

#define HELP_COUNT(a) ((int)(sizeof(a) / sizeof((a)[0])))
#define TUI_COMMAND_HELP_COUNT 18

typedef struct {
    const wchar_t *term;
    const wchar_t *desc;
} HelpEntry;

typedef struct {
    const wchar_t   *title;
    const wchar_t   *intro;
    const HelpEntry *entries;
    int              entry_count;
} HelpPage;

typedef struct {
    const wchar_t  *book_title;
    const HelpPage *pages;
    int             page_count;
} HelpBook;

/* One getter per panel help book. Definitions live in tui/help_books/*.c. */
const HelpBook *tui_help_processes_book(void);
const HelpBook *tui_help_scanner_book(void);
const HelpBook *tui_help_address_table_book(void);
const HelpBook *tui_help_hexview_book(void);

extern const HelpEntry tui_command_help_entries[TUI_COMMAND_HELP_COUNT];

/* Returns the help book for the given panel enum, or NULL if none. */
const HelpBook *tui_help_book_for_panel(int panel);

#endif
