#include "tui.h"

int main(void)
{
    if (tui_init() != 0) {
        return 1;
    }

    tui_run();
    tui_shutdown();

    return 0;
}
