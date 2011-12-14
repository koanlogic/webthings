#include <event2/event.h>

int main(void)
{
    /* Need libevent > 2.0.0 */
    return (LIBEVENT_VERSION_NUMBER > 0x02000000) ? 0 : 1;
}
