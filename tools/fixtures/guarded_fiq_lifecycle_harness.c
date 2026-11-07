/* Test-only C injection into generated copies of ACTUAL candidate C.
 * FIQ disposition is a fake matched to separately opcode-checked assembly.
 * NO real ARM exception, asynchronous delivery, route or hardware claim.
 */
#include "stage90_guarded_read32.h"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
_Alignas(4) const unsigned char stage90_guarded_read32_fault[4]={0};
_Alignas(4) const unsigned char stage90_guarded_read32_recovery[4]={0};
const unsigned char stage90_guarded_fiq_hook_contract[1]={0};
static jmp_buf fatal;
static unsigned selected,mode,fiq_parks,ordinary_fatals,api_returns,restores,checks,cases;
static uint32_t pre,post,out;
#define CHECK(x) do { ++checks;if(!(x)){fprintf(stderr,"FAIL lifecycle line %d: %s\n",__LINE__,#x);exit(1);} } while(0)
/* sites: 1 before-active, 2 after-active, 3 pre-LDR, 4 policy,
 * 5 recovery, 6 before-out, 7 after-out, 8 before-clear, 9 active2,
 * 10 after-clear residual. No simulated instruction-split RAM store. */
void fiq_test_site(unsigned site)
{
    if(site!=selected) return;
    if(site==9) stage90_guarded_read32_state.active=2;
    if(stage90_guarded_read32_state.active!=0) {
        /* Host fake of the separately checked two-store assembly park. */
        stage90_guarded_read32_state.status=7;
        stage90_guarded_read32_state.breadcrumb=0x47524651;
        ++fiq_parks;
    } else ++ordinary_fatals;
    longjmp(fatal,1); /* fake nonreturn, NOT an architectural FIQ return */
}
uint32_t stage90_guarded_read32_irq_save(void){post=pre|0x80u;return pre;}
uint32_t stage90_guarded_read32_cpsr_read(void){return post;}
void stage90_guarded_read32_irq_restore(uint32_t saved){++restores;post=(post&~0x80u)|(saved&0x80u);}
_Noreturn void stage90_guarded_read32_park(void){CHECK(0);abort();}
int stage90_guarded_read32_load_arm(uint32_t address,uint32_t *sample)
{
    fiq_test_site(3);
    if(mode) {
        uint32_t frame[6]={0};frame[5]=(uint32_t)(uintptr_t)stage90_guarded_read32_fault;
        CHECK(stage90_guarded_read32_abort_policy(&stage90_guarded_read32_state,frame,5,address,post)==STAGE90_GUARDED_RECOVERED);
        fiq_test_site(5);
        return 2;
    }
    *sample=0xaabbccdd;return 0;
}
int main(void)
{
    /* Static loop state, like out/counters above, survives longjmp without
     * automatic-local indeterminacy or a GCC -Wclobbered suppression. */
    static unsigned f;
    for(f=0;f<=0x40;f+=0x40) for(selected=1;selected<=10;++selected) {
        ++cases;stage90_guarded_read32_state=(struct stage90_guarded_read32_state){0};
        mode=(selected==4||selected==5);pre=post=0x13u|f;out=9;
        fiq_parks=ordinary_fatals=api_returns=restores=0;
        if(setjmp(fatal)==0) {
            (void)stage90_guarded_read32(0xf9000100,&out);++api_returns;CHECK(0);
        }
        CHECK(api_returns==0 && restores==0);
        CHECK(out==((selected==7||selected==8||selected==10)?0xaabbccdd:9));
        if(selected==1||selected==10) {
            CHECK(ordinary_fatals==1&&fiq_parks==0&&stage90_guarded_read32_state.active==0);
        } else {
            CHECK(fiq_parks==1&&ordinary_fatals==0);
            CHECK(stage90_guarded_read32_state.active==(selected==9?2u:1u));
            CHECK(stage90_guarded_read32_state.status==7&&stage90_guarded_read32_state.breadcrumb==0x47524651);
        }
        CHECK(stage90_guarded_read32_state.fault_count==(selected==5?1u:0u));
    }
    printf("PASS actual-C test-only FIQ injection: %u cases, %u assertions; fake disposition, NOT runtime FIQ\n",cases,checks);
    return 0;
}
