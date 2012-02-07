#include <u/libu.h>

int facility = LOG_LOCAL0;

int main(void)
{
    return (LIBU_VERSION_MAJOR >= 2 && LIBU_VERSION_MINOR >= 3) ? 0 : 1;
}
