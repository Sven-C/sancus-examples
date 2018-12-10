#include <sancus_support/sm_io.h>
#include <sancus_support/timer.h>
#include <sancus/sm_support.h>
#include <string.h>
#include <msp430.h>
#include <sancus_support/sancus_step.h>

#define CAT(x) #x
#define ENABLE_SANCUS_PROTECTION 1
void exit_success(void);
void assert_timing(void);
void leak_latencies(void);

/* ======== TRUSTED CONTEXT ======== */

DECLARE_SM(foo, 0x1234);
#define FOO_SECRET 0xf00

int SM_DATA(foo) foo_initialized;
int SM_DATA(foo) foo_secret1;
int SM_DATA(foo) foo_secret2;
int SM_DATA(foo) foo_secret3;
int SM_DATA(foo) foo_secret4;
int SM_DATA(foo) foo_secret5;

void SM_ENTRY(foo) foo_init()
{
    if (!foo_initialized)
    {
        foo_secret1 = FOO_SECRET | 1;
        foo_secret2 = FOO_SECRET | 2;
        foo_secret3 = FOO_SECRET | 3;
        foo_secret4 = FOO_SECRET | 4;
        foo_secret5 = FOO_SECRET | 5;
        foo_initialized = 1;
    }
}

int SM_ENTRY(foo) get_secret1()
{
    return foo_secret1;
}

int SM_ENTRY(foo) get_secret2(int var1)
{
    int rv;
    __asm__("cmp #0x0, %1           \n\t"
            "jeq 1f                 \n\t"
            ";not eq                \n\t"
            "bis #0x100, %0         \n\t"
            "jmp 2f                 \n\t"
            "1: ;eq                 \n\t"
            "mov #0x0, %0           \n\t"
            "nop                    \n\t"
            "nop                    \n\t"
            "nop                    \n\t"
            "2:                     \n\t"
            :"=r"(rv)
            :"r"(var1)
            :);
    return rv;
}

int SM_ENTRY(foo) get_secret3(int var1, int var2)
{
    return foo_secret3;
}

int SM_ENTRY(foo) get_secret4(int var1, int var2, int var3)
{
    return foo_secret4;
}

int SM_ENTRY(foo) get_secret5(int var1, int var2, int var3, int var4)
{
    return foo_secret5;
}

void SM_ENTRY(foo) foo_disable(void)
{
    sancus_disable(exit_success);
}

/* ======== UNTRUSTED CONTEXT ======== */

volatile int latency;

int main(void)
{
    int duration0, duration1, v1, v2, v3, v4;
    // necessary init
    msp430_io_init();
    __asm__ __volatile__("eint\n\t");
    
    // enable sm
    sancus_enable(&foo);
    foo_init();
    
    assert_timing();
    leak_latencies();
    
    foo_disable();
    
}

void assert_timing(void)
{
    printf("%s", "Asserting the timing of the get_secret2 function\n");
    int v, duration0, duration1;
    timer_tsc_start();
    v = get_secret2(0);
    duration0 = timer_tsc_end();
    
    timer_tsc_start();
    v = get_secret2(1);
    duration1 = timer_tsc_end();
    ASSERT(duration0 == duration1);
}

void leak_latencies(void)
{
    int v;
    printf("%s", "Trying 0\n");
    SANCUS_STEP_INIT;
    v = get_secret2(0);
    printf("Got %d\n", v);
    
    printf("%s", "Trying 1\n");
    SANCUS_STEP_INIT;
    v = get_secret2(1);
    printf("Got %d\n", v);
}

void exit_success(void)
{
    //pr_info("SM disabled; all done!");
    EXIT();
}

/* ======== TIMER A ISR ======== */

/*
 * NOTE: we use a naked asm function here to be able to store IRQ latency.
 * (Timer_A continues counting from zero after IRQ generation)
 */
__attribute__((naked)) __attribute__((interrupt(TIMER_IRQ_VECTOR)))
void timerA_isr_entry(void)
{
    SANCUS_STEP_ISR(print_latency);
}

