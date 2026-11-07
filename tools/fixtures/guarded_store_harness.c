/* Host-only actual-C tests. No ARM execution, MMIO, or exception delivery. */
#include "stage90_guarded_read32.h"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
_Alignas(4) const unsigned char stage90_guarded_read32_fault[4]={0};
_Alignas(4) const unsigned char stage90_guarded_read32_recovery[4]={0};
_Alignas(4) const unsigned char stage90_guarded_write32_fault[4]={0};
_Alignas(4) const unsigned char stage90_guarded_write32_recovery[4]={0};
#ifndef OMIT_HOOK
const unsigned char stage90_guarded_fiq_hook_contract[1]={0};
#endif
static unsigned cases,checks,saves,restores,leaves,parks,attempts,fiq_site;
static uint32_t pre,post,mask_xor,target,behavior,dfsr_fake;
static jmp_buf stop;
#define CHECK(x) do { ++checks; if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);exit(1);} } while(0)
#define CASE() (++cases)
static uint32_t fp(void){return (uint32_t)(uintptr_t)stage90_guarded_write32_fault;}
static uint32_t rp(void){return (uint32_t)(uintptr_t)stage90_guarded_write32_recovery;}
static uint32_t rfp(void){return (uint32_t)(uintptr_t)stage90_guarded_read32_fault;}
static uint32_t rrp(void){return (uint32_t)(uintptr_t)stage90_guarded_read32_recovery;}
static uint32_t fs(unsigned c){return (c&15u)|((c&16u)<<6);}
static int known(unsigned c){return c==3||c==5||c==6||c==7||c==9||c==11||c==13||c==15;}
static struct stage90_guarded_read32_state armed(void)
{
    struct stage90_guarded_read32_state s={0};
    s.active=1;s.operation=1;s.expected_address=0x1000;s.fault_pc=fp();s.recovery_pc=rp();
    s.status=1;s.cpsr_before_mask=pre;s.cpsr_after_mask=post;return s;
}
static void reset(void)
{
    stage90_guarded_read32_state=(struct stage90_guarded_read32_state){0};
    pre=0x60000113;post=pre|0x80;mask_xor=0;target=0x12345678;behavior=0;dfsr_fake=0x80d;
    saves=restores=leaves=parks=attempts=fiq_site=0;
}
uint32_t stage90_guarded_read32_irq_save(void)
{
    ++saves;if((pre&0x0100023fu)==0x13u)post=(pre|0x80)^mask_xor;return pre;
}
uint32_t stage90_guarded_read32_cpsr_read(void){return post;}
void stage90_guarded_read32_irq_restore(uint32_t saved){++restores;post=(post&~0x80u)|(saved&0x80);}
_Noreturn void stage90_guarded_read32_park(void){++parks;longjmp(stop,1);}
/* Called only from generated instrumentation. Fake matched to checked FIQ asm. */
void store_fiq_test_site(unsigned site)
{
    if(site!=fiq_site)return;
    if(site==6)stage90_guarded_read32_state.active=2;
    CHECK(stage90_guarded_read32_state.active!=0);
    stage90_guarded_read32_state.status=7;stage90_guarded_read32_state.breadcrumb=0x47524651;
    ++parks;longjmp(stop,1);
}
int stage90_guarded_read32_load_arm(uint32_t address,uint32_t *sample)
{
    (void)address;CHECK(stage90_guarded_read32_state.operation==0);
    CHECK(stage90_guarded_write32(0x1000,1)==5);*sample=0xaabbccdd;return 0;
}
int stage90_guarded_write32_store_arm(uint32_t address,uint32_t value)
{
    uint32_t p[6]={0},out=9;++leaves;
    CHECK(stage90_guarded_read32_state.active==1&&stage90_guarded_read32_state.operation==1);
    CHECK(stage90_guarded_read32_state.expected_address==address);
    CHECK(stage90_guarded_read32_state.cpsr_before_mask==pre&&stage90_guarded_read32_state.cpsr_after_mask==post);
    CHECK((post&0x80)!=0&&((post^pre)&0x140)==0);
    store_fiq_test_site(2);
    if(behavior==2){ /* Same shared state: either API must return BUSY unchanged. */
        struct stage90_guarded_read32_state before=stage90_guarded_read32_state,after;
        CHECK(stage90_guarded_write32(address,value)==5);CHECK(stage90_guarded_read32(address,&out)==5&&out==9);
        after=stage90_guarded_read32_state;CHECK(memcmp(&before,&after,sizeof before)==0);
    }
    if(behavior==0||behavior==2){++attempts;target=value;store_fiq_test_site(3);return 0;}
    if(behavior>=10){
        switch(behavior){
        case 10:stage90_guarded_read32_state.operation=0;break;
        case 11:stage90_guarded_read32_state.active=2;break;
        case 12:stage90_guarded_read32_state.status=8;break;
        case 13:stage90_guarded_read32_state.fault_count=1;break;
        case 14:stage90_guarded_read32_state.fault_pc+=4;break;
        case 15:stage90_guarded_read32_state.recovery_pc+=4;break;
        case 16:stage90_guarded_read32_state.expected_address+=4;break;
        }
        return 0;
    }
    ++attempts;
    if(behavior==3)target=value; /* Synthetic effect tests status8, NOT architectural possibility. */
    p[5]=fp();if(behavior==6)p[5]+=4;
    enum stage90_guarded_abort_result result=stage90_guarded_read32_abort_policy(
        &stage90_guarded_read32_state,p,behavior==7?(fs(0x16)|0x800):dfsr_fake,address,post);
    if(result!=STAGE90_GUARDED_RECOVERED)stage90_guarded_read32_park();
    CHECK(p[5]==rp());store_fiq_test_site(4);
    return behavior==4?0:behavior==5?2:8;
}
static void policy_tests(void)
{
    for(unsigned f=0;f<=0x40;f+=0x40)for(unsigned c=0;c<32;++c)for(unsigned wn=0;wn<2;++wn){
        CASE();reset();pre|=f;post|=f;
        struct stage90_guarded_read32_state s=armed();uint32_t p[6]={1,2,3,4,5,0};p[5]=fp();
        uint32_t d=fs(c)|(wn<<11);int yes=known(c)&&wn;
        CHECK(stage90_guarded_read32_abort_policy(&s,p,d,s.expected_address,post)==(yes?1:2));
        CHECK(p[5]==(yes?rp():fp())&&p[0]==1&&p[4]==5);
        CHECK(s.status==(yes?8u:7u)&&s.fault_count==1&&s.active==1);
        CHECK(s.fault_dfsr==d&&s.fault_dfar==s.expected_address);
    }
    const unsigned external[]={8,12,14};
    for(unsigned k=0;k<3;++k)for(unsigned wn=0;wn<2;++wn){
        CASE();reset();struct stage90_guarded_read32_state s=armed();uint32_t p[6]={0};p[5]=fp();
        CHECK(stage90_guarded_read32_abort_policy(&s,p,fs(external[k])|(wn<<11),s.expected_address,post)==2);
        CHECK(p[5]==fp()&&s.status==7&&s.active==1&&s.fault_count==1);
    }
    for(unsigned k=0;k<42;++k){
        CASE();reset();struct stage90_guarded_read32_state s=armed();
        uint32_t p[6]={0},d=0x805,a=s.expected_address,c=post;p[5]=fp();
        switch(k){
        case 0:p[5]+=4;break;case 1:a+=4;break;case 2:s.active=2;break;
        case 3:s.expected_address|=1;a=s.expected_address;break;
        case 4:s.fault_pc+=4;p[5]=s.fault_pc;break;case 5:s.recovery_pc+=4;break;
        case 6:s.status=8;break;case 7:s.fault_count=1;break;case 8:s.operation=2;break;
        case 9:s.operation=0;break;case 10:s.fault_pc=rfp();p[5]=rfp();break;
        case 11:s.recovery_pc=rrp();break;case 12:s.operation=0;s.fault_pc=rfp();s.recovery_pc=rrp();p[5]=rfp();break;
        case 13:s.operation=0;s.fault_pc=rfp();s.recovery_pc=rrp();p[5]=fp();d=5;break;
        case 14:s.cpsr_before_mask^=0x40;break;case 15:s.cpsr_after_mask^=0x40;break;
        case 16:s.cpsr_after_mask&=~0x80u;break;case 17:s.cpsr_before_mask^=0x100;break;
        case 18:c^=0x40;break;case 19:c^=0x80;break;case 20:c^=0x20;break;
        case 21:c^=0x200;break;case 22:c^=0x1000000;break;case 23:c^=1;break;
        default:d|=1u<<(k-24+8);break; /* separately exclude known/domain/ExT/WnR/FS bits */
        }
        if(k>=24&&(((1u<<(k-24+8))&0x1cffu)!=0))continue;
        uint32_t pc=p[5];CHECK(stage90_guarded_read32_abort_policy(&s,p,d,a,c)==2);
        CHECK(p[5]==pc&&s.status==7&&s.fault_count==1&&s.active!=0);
    }
    CASE();reset();struct stage90_guarded_read32_state s=armed(),before;
    uint32_t p[6]={0};p[5]=fp();CHECK(stage90_guarded_read32_abort_policy(&s,p,0x180d,s.expected_address,post)==1);
    p[5]=fp();CHECK(stage90_guarded_read32_abort_policy(&s,p,0x80d,s.expected_address,post)==2&&p[5]==fp()&&s.fault_count==1);
    CASE();s=armed();s.active=0;before=s;p[5]=fp();
    CHECK(stage90_guarded_read32_abort_policy(&s,p,~0u,0,0)==0&&memcmp(&s,&before,sizeof s)==0&&p[5]==fp());
    CASE();s=armed();CHECK(stage90_guarded_read32_abort_policy(&s,0,0x805,s.expected_address,post)==2);
    CHECK(stage90_guarded_read32_abort_policy(0,p,0x805,0,post)==2);
}
static void wrapper_tests(void)
{
    for(unsigned f=0;f<=0x40;f+=0x40)for(unsigned a=0;a<=0x100;a+=0x100)
    for(unsigned i=0;i<=0x80;i+=0x80)for(unsigned b=0;b<4;++b){
        CASE();reset();pre=0x60000013|f|a|i;post=pre;behavior=b;
        int rc=stage90_guarded_write32(0x1000,0xa5a55a5a);
        CHECK(rc==((b==1||b==3)?8:0));CHECK(target==(b==1?0x12345678:0xa5a55a5a));
        CHECK(attempts==1&&leaves==1&&parks==0&&post==pre);
        CHECK(stage90_guarded_read32_state.active==0&&stage90_guarded_read32_state.operation==1);
        CHECK(stage90_guarded_read32_state.fault_count==((b==1||b==3)?1u:0u));
    }
    for(unsigned off=1;off<4;++off){
        CASE();reset();CHECK(stage90_guarded_write32(0x1000+off,0)==4&&saves==0&&leaves==0);
    }
    CASE();reset();CHECK(stage90_guarded_write32(0,0)==0&&target==0); /* zero is not an out pointer */
    const uint32_t invalid[]={0x10,0x17,0x33,0x213,0x01000013};
    for(unsigned k=0;k<sizeof invalid/sizeof invalid[0];++k){
        CASE();reset();pre=post=invalid[k];CHECK(stage90_guarded_write32(0x1000,1)==6&&leaves==0&&restores==0&&post==pre);
    }
    for(unsigned bit=0;bit<32;++bit)if(((1u<<bit)&(STAGE90_GUARD_STABLE_CPSR|0x100))!=0){
        CASE();reset();mask_xor=1u<<bit;CHECK(stage90_guarded_write32(0x1000,1)==6&&leaves==0&&restores==1);
        CHECK(stage90_guarded_read32_state.active==0&&stage90_guarded_read32_state.status==6);
    }
    for(unsigned active=1;active<=2;++active){
        CASE();reset();stage90_guarded_read32_state.active=active;
        struct stage90_guarded_read32_state before=stage90_guarded_read32_state,after;
        CHECK(stage90_guarded_write32(0x1000,1)==5&&leaves==0&&restores==1&&post==pre);
        after=stage90_guarded_read32_state;CHECK(memcmp(&before,&after,sizeof before)==0);
    }
    CASE();reset();stage90_guarded_read32_state.operation=1;uint32_t out=9;
    CHECK(stage90_guarded_read32(0x1000,&out)==0&&out==0xaabbccdd&&stage90_guarded_read32_state.operation==0);
    static unsigned b;
    for(b=4;b<=16;++b){
        if(b==8||b==9)continue;
        CASE();reset();behavior=b;
        if(setjmp(stop)==0){(void)stage90_guarded_write32(0x1000,1);CHECK(0);}
        CHECK(parks==1&&restores==0&&stage90_guarded_read32_state.active!=0&&stage90_guarded_read32_state.status==7);
    }
}
#ifdef FIQ_INSTRUMENTED
static void fiq_tests(void)
{
    static unsigned site;
    for(site=1;site<=6;++site){
        CASE();reset();fiq_site=site;behavior=site==4?1:0;
        if(setjmp(stop)==0){(void)stage90_guarded_write32(0x1000,1);CHECK(0);}
        CHECK(parks==1&&restores==0&&stage90_guarded_read32_state.active==(site==6?2u:1u));
        CHECK(stage90_guarded_read32_state.status==7&&stage90_guarded_read32_state.breadcrumb==0x47524651);
        CHECK(target==((site==3||site==5)?1u:0x12345678));
    }
}
#endif
int main(void)
{
    policy_tests();wrapper_tests();
#ifdef FIQ_INSTRUMENTED
    fiq_tests();
#endif
    printf("PASS store actual C: %u cases, %u assertions; host fake only, write fault side effect INDETERMINATE\n",cases,checks);
    return 0;
}
