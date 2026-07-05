#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>
#include <wchar.h>
#include "tui/render.h"

int screen_alloc(Screen *screen, int w, int h)
{
    screen->cells = (CHAR_INFO *)calloc((size_t)w * (size_t)h, sizeof(CHAR_INFO));
    if (!screen->cells) {
        return -1;
    }
    screen->w = w;
    screen->h = h;
    return 0;
}

void screen_free(Screen *screen)
{
    free(screen->cells);
    screen->cells = NULL;
    screen->w = 0;
    screen->h = 0;
}

void screen_clear(Screen *screen, WORD attr)
{
    for (int i = 0; i < screen->w * screen->h; i++) {
        screen->cells[i].Char.UnicodeChar = L' ';
        screen->cells[i].Attributes = attr;
    }
}

void screen_put(Screen *screen, int x, int y, wchar_t ch, WORD attr)
{
    if (x < 0 || x >= screen->w || y < 0 || y >= screen->h) {
        return;
    }
    screen->cells[y * screen->w + x].Char.UnicodeChar = ch;
    screen->cells[y * screen->w + x].Attributes = attr;
}

void screen_fill_row(Screen *screen, int y, wchar_t ch, WORD attr, int x0, int x1)
{
    for (int x = x0; x <= x1; x++) {
        screen_put(screen, x, y, ch, attr);
    }
}

void screen_text(Screen *screen, int x, int y, const wchar_t *text, WORD attr)
{
    while (*text && x < screen->w) {
        screen_put(screen, x++, y, *text++, attr);
    }
}

void screen_text_right(Screen *screen, int right_x, int y, const wchar_t *text, WORD attr)
{
    size_t len = wcslen(text);
    int x = right_x - (int)len + 1;
    if (x < 0) {
        x = 0;
    }
    screen_text(screen, x, y, text, attr);
}

void screen_present(Screen *screen, HANDLE out)
{
    SMALL_RECT region = { 0, 0, (SHORT)(screen->w - 1), (SHORT)(screen->h - 1) };
    COORD size   = { (SHORT)screen->w, (SHORT)screen->h };
    COORD origin = { 0, 0 };
    WriteConsoleOutputW(out, screen->cells, size, origin, &region);
}
