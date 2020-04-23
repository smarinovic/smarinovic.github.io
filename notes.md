### C wrapper to run a shell code

```
#include <stdio.h>

char shellcode[] = .... ;

int main(int argc, char **argv) {
    (*(void (*)()) shellcode)();
    return(0);
}
```

*More examples can be found at: http://disbauxes.upc.es/code/two-basic-ways-to-run-and-test-shellcode/*

