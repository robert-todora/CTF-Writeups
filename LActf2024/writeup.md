## LA CTF 2024

### Pwn: Aplet123

This pwn challenge involved leaking a stack canary by supplying the program with a specific input combined with a buffer overflow. After performing the buffer overflow, the program will print out 4 bytes immediately following the word "i'm" if it is found in your input. So by figuring out the number of bytes necessary to reach the null byte of the canary, we can end our payload with "i'm" in order to overwrite the null byte of the canary and leak the stack canary. Once we have done this, we grab that value and overflow the program again, this time overwriting the return address with the stack canary value followed by the address of the print flag function.

Thanks for reading!
