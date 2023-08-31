//
//  helper.c
//  helper
//

#include <mach/mach_types.h>
#include <IOKit/IOLib.h>
#include <libkern/c++/OSBoolean.h>

kern_return_t helper_start(kmod_info_t * ki, void *d);
kern_return_t helper_stop(kmod_info_t *ki, void *d);


// fake entitlement checkers
class IOFuzzClient{
public:
    OSObject * copyClientEntitlement(task_t task, const char *entitlement);
    OSObject * AMFIcopyClientEntitlement(task_t task, const char *entitlement);
};

OSObject * IOFuzzClient::copyClientEntitlement( task_t task,const char * entitlement ){
    return kOSBooleanTrue;
}

OSObject * IOFuzzClient::AMFIcopyClientEntitlement( task_t task,const char * entitlement ){
    return kOSBooleanTrue;
}

// Profiling functions
void COVRT(){

    __asm__ __volatile__(
                 "_COVRT:\n"
                 "SUB SP, SP, #0x100\n"
                 "STR X31, [SP, #0xf8]\n"
                 "STR X30, [SP, #0xf0]\n"
                 "STR X29, [SP, #0xe8]\n"
                 "STR X28, [SP, #0xe0]\n"
                 "STR X27, [SP, #0xd8]\n"
                 "STR X26, [SP, #0xd0]\n"
                 "STR X25, [SP, #0xc8]\n"
                 "STR X24, [SP, #0xc0]\n"
                 "STR X23, [SP, #0xb8]\n"
                 "STR X22, [SP, #0xb0]\n"
                 "STR X21, [SP, #0xa8]\n"
                 "STR X20, [SP, #0xa0]\n"
                 "STR X19, [SP, #0x98]\n"
                 "STR X18, [SP, #0x90]\n"
                 "STR X17, [SP, #0x88]\n"
                 "STR X16, [SP, #0x80]\n"
                 "STR X15, [SP, #0x78]\n"
                 "STR X14, [SP, #0x70]\n"
                 "STR X13, [SP, #0x68]\n"
                 "STR X12, [SP, #0x60]\n"
                 "STR X11, [SP, #0x58]\n"
                 "STR X10, [SP, #0x50]\n"
                 "STR X9,  [SP, #0x48]\n"
                 "STR X8,  [SP, #0x40]\n"
                 "STR X7,  [SP, #0x38]\n"
                 "STR X6,  [SP, #0x30]\n"
                 "STR X5,  [SP, #0x28]\n"
                 "STR X4,  [SP, #0x20]\n"
                 "STR X3,  [SP, #0x18]\n"
                 "STR X2,  [SP, #0x10]\n"
                 "STR X1,  [SP, #0x8]\n"
                 "STR X0,  [SP, #0x0]\n"
                 "SUB SP, SP, #0x50\n"
                 "ADD X29, SP, #0x40\n"
            );
    
    IOLog("Instrumented Function called. Edit this function to do other profiling works. e.f. Coverage Collection");
    
    __asm__ __volatile__(
                "ADD SP, SP, #0x50\n"
                "LDR X31, [SP, #0xf8]\n"
                "LDR X30, [SP, #0xf0]\n"
                "LDR X29, [SP, #0xe8]\n"
                "LDR X28, [SP, #0xe0]\n"
                "LDR X27, [SP, #0xd8]\n"
                "LDR X26, [SP, #0xd0]\n"
                "LDR X25, [SP, #0xc8]\n"
                "LDR X24, [SP, #0xc0]\n"
                "LDR X23, [SP, #0xb8]\n"
                "LDR X22, [SP, #0xb0]\n"
                "LDR X21, [SP, #0xa8]\n"
                "LDR X20, [SP, #0xa0]\n"
                "LDR X19, [SP, #0x98]\n"
                "LDR X18, [SP, #0x90]\n"
                "LDR X17, [SP, #0x88]\n"
                "LDR X16, [SP, #0x80]\n"
                "LDR X15, [SP, #0x78]\n"
                "LDR X14, [SP, #0x70]\n"
                "LDR X13, [SP, #0x68]\n"
                "LDR X12, [SP, #0x60]\n"
                "LDR X11, [SP, #0x58]\n"
                "LDR X10, [SP, #0x50]\n"
                "LDR X9,  [SP, #0x48]\n"
                "LDR X8,  [SP, #0x40]\n"
                "LDR X7,  [SP, #0x38]\n"
                "LDR X6,  [SP, #0x30]\n"
                "LDR X5,  [SP, #0x28]\n"
                "LDR X4,  [SP, #0x20]\n"
                "LDR X3,  [SP, #0x18]\n"
                "LDR X2,  [SP, #0x10]\n"
                "LDR X1,  [SP, #0x8]\n"
                "LDR X0,  [SP, #0x0]\n"
                "ADD SP, SP, #0x100\n"
                "RET");
}

void COVIOCTL_COVWRIT(){
    __asm__ __volatile__(
                 "_COVIOCTL_COVWRIT:\n"
                 "SUB SP, SP, #0x100\n"
                 "STR X31, [SP, #0xf8]\n"
                 "STR X30, [SP, #0xf0]\n"
                 "STR X29, [SP, #0xe8]\n"
                 "STR X28, [SP, #0xe0]\n"
                 "STR X27, [SP, #0xd8]\n"
                 "STR X26, [SP, #0xd0]\n"
                 "STR X25, [SP, #0xc8]\n"
                 "STR X24, [SP, #0xc0]\n"
                 "STR X23, [SP, #0xb8]\n"
                 "STR X22, [SP, #0xb0]\n"
                 "STR X21, [SP, #0xa8]\n"
                 "STR X20, [SP, #0xa0]\n"
                 "STR X19, [SP, #0x98]\n"
                 "STR X18, [SP, #0x90]\n"
                 "STR X17, [SP, #0x88]\n"
                 "STR X16, [SP, #0x80]\n"
                 "STR X15, [SP, #0x78]\n"
                 "STR X14, [SP, #0x70]\n"
                 "STR X13, [SP, #0x68]\n"
                 "STR X12, [SP, #0x60]\n"
                 "STR X11, [SP, #0x58]\n"
                 "STR X10, [SP, #0x50]\n"
                 "STR X9,  [SP, #0x48]\n"
                 "STR X8,  [SP, #0x40]\n"
                 "STR X7,  [SP, #0x38]\n"
                 "STR X6,  [SP, #0x30]\n"
                 "STR X5,  [SP, #0x28]\n"
                 "STR X4,  [SP, #0x20]\n"
                 "STR X3,  [SP, #0x18]\n"
                 "STR X2,  [SP, #0x10]\n"
                 "STR X1,  [SP, #0x8]\n"
                 "STR X0,  [SP, #0x0]\n"
                 "SUB SP, SP, #0x50\n"
                 "ADD X29, SP, #0x40\n"
            );
    
    IOLog("Instrumented Function called. Edit this function to do other profiling works. e.f. Coverage Collection");
    
    __asm__ __volatile__(
                 "ADD SP, SP, #0x50\n"
                 "LDR X31, [SP, #0xf8]\n"
                 "LDR X30, [SP, #0xf0]\n"
                 "LDR X29, [SP, #0xe8]\n"
                 "LDR X28, [SP, #0xe0]\n"
                 "LDR X27, [SP, #0xd8]\n"
                 "LDR X26, [SP, #0xd0]\n"
                 "LDR X25, [SP, #0xc8]\n"
                 "LDR X24, [SP, #0xc0]\n"
                 "LDR X23, [SP, #0xb8]\n"
                 "LDR X22, [SP, #0xb0]\n"
                 "LDR X21, [SP, #0xa8]\n"
                 "LDR X20, [SP, #0xa0]\n"
                 "LDR X19, [SP, #0x98]\n"
                 "LDR X18, [SP, #0x90]\n"
                 "LDR X17, [SP, #0x88]\n"
                 "LDR X16, [SP, #0x80]\n"
                 "LDR X15, [SP, #0x78]\n"
                 "LDR X14, [SP, #0x70]\n"
                 "LDR X13, [SP, #0x68]\n"
                 "LDR X12, [SP, #0x60]\n"
                 "LDR X11, [SP, #0x58]\n"
                 "LDR X10, [SP, #0x50]\n"
                 "LDR X9,  [SP, #0x48]\n"
                 "LDR X8,  [SP, #0x40]\n"
                 "LDR X7,  [SP, #0x38]\n"
                 "LDR X6,  [SP, #0x30]\n"
                 "LDR X5,  [SP, #0x28]\n"
                 "LDR X4,  [SP, #0x20]\n"
                 "LDR X3,  [SP, #0x18]\n"
                 "LDR X2,  [SP, #0x10]\n"
                 "LDR X1,  [SP, #0x8]\n"
                 "LDR X0,  [SP, #0x0]\n"
                 "ADD SP, SP, #0x100\n"
                 "RET");
}

kern_return_t helper_start(kmod_info_t * ki, void *d)
{
    return KERN_SUCCESS;
}

kern_return_t helper_stop(kmod_info_t *ki, void *d)
{
    return KERN_SUCCESS;
}
