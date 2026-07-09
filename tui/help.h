#ifndef HELP_H
#define HELP_H

#include <wchar.h>

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

const HelpBook *tui_help_book_for_panel(int panel);

#endif
