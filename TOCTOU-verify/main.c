#include <msp430.h>
#include <stdio.h>
#include <sancus/sm_support.h>
#include <sancus_support/sm_io.h>
#include "foo.h"
#include "bar.h"
#include <sancus_support/timer.h>

#define HW_IRQ_LATENCY 34

int inst_lat;

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

volatile int bar_disabled = 0;

int main()
{
    int rv, u, f;
    msp430_io_init();
    sancus_enable(&foo);
    //pr_sm_info(&foo);
    sancus_enable(&bar);
    //pr_sm_info(&bar);
    
    print_foo_secret();
    
    timer_irq(0x7063);
    rv = enter_foo();
    
    u = unpr_mul(rv, 100, 35);
    f = foo_mul(rv, 100, 35);
    ASSERT( u==f );
    printf("%s", "All done, bye!\n");
    EXIT();
}

/* =========================== TIMER A ISR =============================== */

int reg2, reg4, reg5, reg6, reg7, reg8, reg9, reg10,
        reg11, reg12, reg13, reg14, reg15;
void timerA_isr(void)
{
    TACTL = TACTL_DISABLE;
    //printf("%s", "Hello from timer isr\n");
    void* cont_ptr;
    if (!bar_disabled)
    {
        bar_disabled = 1;
        asm("mov #cont_lbl, %0                      \n\t"
            "mov r1, &__unprotected_sp              \n\t"
            :"=r"(cont_ptr)::);
        bar_disable(cont_ptr);
        asm("cont_lbl: mov &__unprotected_sp, r1    \n\t"
            "pop r7                                 \n\t"
            "pop r6                                 \n\t"
            "add #0x2, r1                           \n\t");
        timer_irq(0xb4);
    }
    else
    {
        __asm__("mov r2, &reg2          \n\t"
                "mov r4, &reg4          \n\t"
                "mov r5, &reg5          \n\t"
                "mov r6, &reg6          \n\t"
                "mov r7, &reg7          \n\t"
                "mov r8, &reg8          \n\t"
                "mov r9, &reg9          \n\t"
                "mov r10, &reg10        \n\t"
                "mov r11, &reg11        \n\t"
                "mov r12, &reg12        \n\t"
                "mov r13, &reg13        \n\t"
                "mov r14, &reg14        \n\t"
                "mov r15, &reg15        \n\t"
                ::);
        printf("%s", "Dumping registers\n");
        printf("Secret passed by foo to bar: %d\n", reg15);
    }
}


/*
 * NOTE: we use a naked asm function here to be able to store IRQ latency.
 * (Timer_A continues counting from zero after IRQ generation)
 */
__attribute__((naked)) __attribute__((interrupt(TIMER_IRQ_VECTOR)))
void timerA_isr_entry(void)
{
    asm("mov &%0, &inst_lat             \n\t"
        "cmp #0x0, r1                   \n\t"
        "jne no_sm                      \n\t"
        "; isr interrupted an sm        \n\t"
        "mov &__unprotected_sp, r1      \n\t"
        "; push #0x1 here               \n\t"
        "; to remember how to return    \n\t"
        "push #0x1                      \n\t"
        "jmp cont                       \n\t"
        "no_sm:                         \n\t"
        "; make sure that bar is ok     \n\t"
        "cmp #0x0, &bar_disabled        \n\t"
        "jeq 1f                         \n\t"
        "mov &__unprotected_sp, r1      \n\t"
        "; same as the other case       \n\t"
        "1:                             \n\t"
        "push #0x0                      \n\t"
        "cont:                          \n\t"
        "push r15                       \n\t"
        "push r14                       \n\t"
        "push r13                       \n\t"
        "push r12                       \n\t"
        "push r11                       \n\t"
        "push r10                       \n\t"
        "push r9                        \n\t"
        "push r8                        \n\t"
        "push r7                        \n\t"
        "push r6                        \n\t"
        "push r5                        \n\t"
        "push r4                        \n\t"
        "call #timerA_isr               \n\t"
        "pop  r4                        \n\t"
        "pop  r5                        \n\t"
        "pop  r6                        \n\t"
        "pop  r7                        \n\t"
        "pop  r8                        \n\t"
        "pop  r9                        \n\t"
        "pop  r10                       \n\t"
        "pop  r11                       \n\t"
        "pop  r12                       \n\t"
        "pop  r13                       \n\t"
        "pop  r14                       \n\t"
        "pop  r15                       \n\t"
        "; we free here so we can do it \n\t"
        "; just once                    \n\t"
        "add #0x2, r1                   \n\t"
        "cmp #0x0, -2(r1)               \n\t"
        "jeq 1f                         \n\t"
        "; resume interrupted sm        \n\t"
        "br r15                         \n\t"
        "1:                             \n\t"
        "; return normally              \n\t"
        "reti                           \n\t"
        ::"m"(TAR):);
}
