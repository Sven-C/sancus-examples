#include "foo.h"
#include "bar.h"
#include <sancus_support/sm_io.h>

DECLARE_SM(foo, 0x1234);

const int SM_DATA(foo) foo_secret = 0x80;

int SM_FUNC(foo) foo_div( int i, unsigned int j)
{
    return (i / j);
}

void SM_ENTRY(foo) print_foo_secret(void)
{
    pr_info1("Foo secret: %d\n", foo_secret);
}

int SM_ENTRY(foo) enter_foo(void)
{
    int foo_secret = 0x80;
    int j, k = bar_lookup(foo_secret);

    j = foo_div(k, 5) % foo_secret;
    return foo_secret * j;
}
