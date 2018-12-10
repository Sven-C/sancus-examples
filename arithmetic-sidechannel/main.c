#include <msp430.h>
#include <stdio.h>
#include <sancus/sm_support.h>
#include <sancus_support/sm_io.h>
#include <sancus_support/timer.h>
#include "foo.h"
#include "bar.h"

int unpr_mul(int a, int b, int c)
{
    return (a * b) % c;
}

/* Also include a protected foo function here to test arithmetic inlining
   across compilation units. */
int SM_ENTRY(foo) foo_mul(int a, int b, int c)
{
    return (a * b) % c;
}

int main()
{
    int rv, u, f;
    int duration;
    msp430_io_init();
    sancus_enable(&foo);
    //pr_sm_info(&foo);
    //sancus_enable(&bar);
    //pr_sm_info(&bar);

    for (int i = 0; i < 0x10; i++)
    {
        for (int j = 0; j < 0x10; j++)
        {
            timer_tsc_start();
            volatile int rv = enter_foo(j, i);
            duration = timer_tsc_end();
            printf("%d, %d took %d\n", j, i, duration);
        }
    }
    EXIT();
}
