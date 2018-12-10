#include <sancus_support/sm_io.h>
#include <sancus_support/pmodkypd.h>

void press_callback(PmodKypdKey key)
{
   pr_info1("Key '%c' pressed!\n", pmodkypd_key_to_char(key));
}

void release_callback(PmodKypdKey key)
{
   pr_info1("Key '%c' released\n", pmodkypd_key_to_char(key));
}

int main()
{
    msp430_io_init();
    pmodkypd_init(press_callback, release_callback);

    pr_info("waiting for key presses...");
    while(1)
    {
        pmodkypd_poll();
    }
    
    pr_info("exiting...");
    EXIT();
}
