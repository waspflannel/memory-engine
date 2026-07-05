#ifndef TUI_RENDER_H
#define TUI_RENDER_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/*
 * A simple off-screen text buffer: a grid of character cells you draw into,
 * then blit to the console in one call. This knows nothing about MemForge —
 * it just puts characters and colors on a grid. "How to draw", not "what".
 */
typedef struct {
    CHAR_INFO *cells;
    int        w;
    int        h;
} Screen;

int  screen_alloc(Screen *screen, int w, int h);   /* 0 on success, -1 if out of memory */
void screen_free(Screen *screen);

void screen_clear(Screen *screen, WORD attr);
void screen_put(Screen *screen, int x, int y, wchar_t ch, WORD attr);
void screen_fill_row(Screen *screen, int y, wchar_t ch, WORD attr, int x0, int x1);
void screen_text(Screen *screen, int x, int y, const wchar_t *text, WORD attr);
void screen_text_right(Screen *screen, int right_x, int y, const wchar_t *text, WORD attr);

void screen_present(Screen *screen, HANDLE out);   /* blit the buffer to the console */

#endif
