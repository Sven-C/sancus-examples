#ifndef FOO_H_INC
#define FOO_H_INC

#include <sancus/sm_support.h>

extern struct SancusModule foo;

void SM_ENTRY(foo) print_foo_secret(void);
int SM_ENTRY(foo) enter_foo(void);

#endif
