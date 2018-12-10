#include <sancus_support/sm_io.h>
#include <sancus_support/timer.h>
#include <string.h>

static char passwd[] = "xD";

int check_passwd(char* provided_passwd);

int main()
{
    int duration;
    /*
     * Holds our current guess
     * Assume all passwords are less than 128 chars
     */
    char current[128] = {0};
    msp430_io_init();
    // enable interrupts
    asm("eint\n\t");
    
    // tracks length of current guess without null byte
    char current_len = 0;
    
    // repeatedly bruteforce one char at a time
    while (!check_passwd(current))
    {
        int valid = 0;
        char bestChar = '\0';
        unsigned int bestTime = 0xffff;
        for (char c = '0'; c <= 'z'; c++)
        {
            current[current_len] = c;
            timer_tsc_start();
            volatile int v = check_passwd(current);
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
    pr_info("exiting...");
    EXIT();
}

/*
 * Returns 0 if provided_passwd != passwd, else 1
 */
int check_passwd(char* provided_passwd)
{
    int len;
    len = strlen(passwd); // length excluding the null byte
    for (int i = 0; i <= len; i++)
    {
        //printf("%s: %d\n", provided_passwd, i);
        if (provided_passwd[i] != passwd[i])
            return 0;
    }
    return 1;
}
