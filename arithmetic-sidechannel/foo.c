#include "foo.h"
#include "bar.h"
#include <sancus_support/sm_io.h>

DECLARE_SM(foo, 0x1234);

int SM_FUNC(foo) foo_div( int i, unsigned int j)
{
    return (i / j);
}

int SM_ENTRY(foo) enter_foo( int a, int b )
{
    //int j, k = bar_lookup(i);
    return a*b;
}
