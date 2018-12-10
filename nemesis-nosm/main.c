#include <sancus_support/sm_io.h>
#include <sancus_support/timer.h>
#include <sancus/sm_support.h>
#include <string.h>
#include <msp430.h>

#define CAT(x) #x
#define BUF_LEN 128
void nemesis(void);
void nemesis_assert(void);
void exit_success(void);
void timerA_isr(void);

/* ======== VAULT WORLD SM ======== */

#define VAULT_SECRET_CST    0xbeef
#define VAULT_PASSWD        "foobar"
#define VAULT_PASSWD_LEN    7 //8+1 for null byte

int vault_initialized = 0;
int vault_secret;
char vault_passwd[VAULT_PASSWD_LEN];
int const vault_secret_const = VAULT_SECRET_CST;
char const vault_passwd_const[VAULT_PASSWD_LEN] = VAULT_PASSWD;

void vault_init()
{
    if (!vault_initialized)
    {
        // copy the constant chars into the buffer for the passwd
        memcpy(vault_passwd, vault_passwd_const, VAULT_PASSWD_LEN);
        vault_secret = vault_secret_const;
        vault_initialized = 1;
    }
    printf("%s \n", vault_passwd);
}

/**
 * Returns 0 on failure, and the secret on success
 * Contains a nemesis style timing sidechannel
 * */
int __attribute__((noinline)) get_secret(char* provided_passwd)
{
    int len = VAULT_PASSWD_LEN;
    int rv, success = 1;
    
    /*
     * Provided password must match password exactly, including the nullbyte at the end
     * This prevents provided password from being accepted if it starts with passwd
     */
    /*
    for (int i = 0; i < len; i++)
    {
        if (provided_passwd[i] != vault_passwd[i])
            success = 0;
        else
            __asm__("nop\n\t"); // prevent sidechannel timing attack
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
                            "mov.b @(r8), r5                \n\t"
                            "mov.b @(r10), r6               \n\t"
                            "cmp.b @(r8), @(r10)            \n\t"
                            "jeq eqLp                       \n\t"
                            "mov #0xfedc, r7                \n\t"
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
                            : "r" (provided_passwd), "r" (len), "m" (TAR)
                            : "r5", "r6", "r7", "r8", "r9", "r10", "r11");
    
    // change this into assembly to ensure that amount of cycles is not dependant on success
    /*
    if (success)
    {
        rv = vault_secret;
    }
    else
    {
        rv = 0;
    }
    */
    /*
    __asm__("tst %1                                                         \n\t"
            "jz iszero2                                                     \n\t"
            "mov &vault_secret, %0; success != 0: thus rv=secret. 3 cycles  \n\t"
            "jmp end2  ; skip the rest. 2 cycles                            \n\t"
            "iszero2: mov #0, %0 ; success==0, so rv=0. 1 cycles            \n\t"
            "nop  ; necessary for timing channel. 1 cycle                   \n\t"
            "nop  ; necessary for timing channel. 1 cycle                   \n\t"
            "nop  ; necessary for timing channel. 1 cycle                   \n\t"
            "nop  ; necessary for timing channel. 1 cycle                   \n\t"
            "end2: nop ; end of assembly                                    \n\t"
            : "=r" (rv)
            : "r" (success)
            : "r7"
            );
    */
    return rv;
}

void vault_disable(void)
{
    exit_success();
}

/* ======== UNTRUSTED CONTEXT ======== */

volatile int latency;

int main(void)
{
    // necessary init
    msp430_io_init();
    __asm__ __volatile__("eint\n\t");
    
    // enable sm
    //sancus_enable(&vault);
    vault_init();
    
    ASSERT(get_secret(VAULT_PASSWD) == VAULT_SECRET_CST);
    nemesis_assert();
    // leak different func
    nemesis();
    
    vault_disable();
    
}

void nemesis(void)
{
    /*
     * Holds our current guess
     * Assume all passwords are less than 128 chars
     */
    char current[BUF_LEN] = {0};
    // tracks length of current guess without null byte
    char current_len = 0;
    
    // repeatedly bruteforce one char at a time for timing channel 1
    while (!get_secret(current))
    {
        int valid = 0;
        char bestChar = '\0';
        unsigned int bestTime = 0xfedc;
        for (char c = '0'; c <= 'z'; c++)
        {
            current[current_len] = c;
            timer_irq(59+current_len*(26)); // YEY FOR MAGIC NUMBERS
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
    }
    printf("Recovered passwd: %s\n", current);
}

void nemesis_assert(void)
{
    int duration;
    /*
     * Holds our current guess
     * Assume all passwords are less than 128 chars
     */
    char current[BUF_LEN] = {0};
    // tracks length of current guess without null byte
    char current_len = 0;
    
    // repeatedly bruteforce one char at a time for timing channel 1
    while (!get_secret(current) && current_len < VAULT_PASSWD_LEN)
    {
        int valid = 0;
        char bestChar = '\0';
        unsigned int bestTime = 0xfedc;
        for (char c = '0'; c <= 'z'; c++)
        {
            current[current_len] = c;
            timer_tsc_start();
            volatile int v = get_secret(current);
            duration = timer_tsc_end();
            if (!valid)
            {
                bestTime = duration;
                bestChar = c;
                valid = 1;
            }
            else
            {
                ASSERT(duration == bestTime);
            }
        }
        //printf("Best char: 0x%.2x\n", bestChar);
        /*
         * Change best char to correct one, so that independent
         * how many chars are correct, the code is balanced
         */
        if (bestChar != VAULT_PASSWD[current_len])
        {
            bestChar = VAULT_PASSWD[current_len];
            //printf("%s", "Changing best char\n");
        }
        // write best char into buf and continue with next char
        current[current_len] = bestChar;
        current_len++;
        //printf("Current: %s\n", current);
    }
    printf("%s", "Nemesis assert ok\n");
}

void exit_success(void)
{
    //pr_info("SM disabled; all done!");
    EXIT();
}

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
    asm("mov &%0, &latency          \n\t"
        "push r15                   \n\t"
        "push r14                   \n\t"
        "push r13                   \n\t"
        "push r12                   \n\t"
        "push r11                   \n\t"
        "push r10                   \n\t"
        "push r9                    \n\t"
        "push r8                    \n\t"
        "push r7                    \n\t"
        "push r6                    \n\t"
        "push r5                    \n\t"
        "push r4                    \n\t"
        "call #timerA_isr           \n\t"
        "pop  r4                    \n\t"
        "pop  r5                    \n\t"
        "pop  r6                    \n\t"
        "pop  r7                    \n\t"
        "pop  r8                    \n\t"
        "pop  r9                    \n\t"
        "pop  r10                   \n\t"
        "pop  r11                   \n\t"
        "pop  r12                   \n\t"
        "pop  r13                   \n\t"
        "pop  r14                   \n\t"
        "pop  r15                   \n\t"
        "reti                       \n\t"
        ::"m"(TAR):);
}
