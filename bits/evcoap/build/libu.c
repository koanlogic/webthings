#include <u/libu.h>

int facility = LOG_LOCAL0;

int main(void)
{
    return (LIBU_VERSION_MAJOR >= 2) ? 0 : 1;
}
