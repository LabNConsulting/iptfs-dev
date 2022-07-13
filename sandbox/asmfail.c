
#define _static_cpu_has(bit)      asm ("": : "i" (bit)); 
//static inline  __attribute__((always_inline)) 
//void _static_cpu_has(unsigned short bit)
//{
//      asm ("": : "i" (bit)); 
//}
void
GccCompileError_init(void)
{
    _static_cpu_has(( 9*32+10)) ;
}

