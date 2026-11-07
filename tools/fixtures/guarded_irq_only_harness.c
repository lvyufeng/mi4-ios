/* Original host-only tests: actual candidate C, fake ARM leaf; no CPU/FIQ delivery. */
#include "stage90_guarded_read32.h"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Alignas(4) const unsigned char stage90_guarded_read32_fault[4] = {0};
_Alignas(4) const unsigned char stage90_guarded_read32_recovery[4] = {0};
#ifndef OMIT_HOOK
const unsigned char stage90_guarded_fiq_hook_contract[1] = {0}; /* host fake only */
#endif
static unsigned cases, checks, leaves, saves, restores, parks;
static uint32_t pre, post, mask_xor, value;
static int behavior, expected_park;
static jmp_buf escape;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); exit(1); } } while (0)
#define CASE() (++cases)
static uint32_t fpc(void) { return (uint32_t)(uintptr_t)stage90_guarded_read32_fault; }
static uint32_t rpc(void) { return (uint32_t)(uintptr_t)stage90_guarded_read32_recovery; }
static uint32_t fs(unsigned code) { return (code & 15u) | ((code & 16u) << 6); }
static int documented(unsigned c) { return c==3||c==5||c==6||c==7||c==8||c==9||c==11||c==12||c==13||c==14||c==15; }
static struct stage90_guarded_read32_state armed(uint32_t f)
{
    struct stage90_guarded_read32_state s = {0};
    s.active=1; s.expected_address=0xf9000100u; s.fault_pc=fpc(); s.recovery_pc=rpc();
    s.status=STAGE90_GUARDED_ARMED; s.cpsr_before_mask=0x13u|f; s.cpsr_after_mask=0x93u|f;
    return s;
}
static void frame_init(uint32_t *p) { for(unsigned i=0;i<6;++i) p[i]=0x12340000u+i; p[5]=fpc(); }
uint32_t stage90_guarded_read32_irq_save(void)
{
    ++saves;
    if ((pre & 0x0100023fu)==0x13u) post=(pre|0x80u)^mask_xor;
    return pre;
}
uint32_t stage90_guarded_read32_cpsr_read(void) { return post; }
void stage90_guarded_read32_irq_restore(uint32_t saved)
{
    ++restores; post=(post & ~0x80u)|(saved & 0x80u); /* ONLY I, preserve F/A */
}
_Noreturn void stage90_guarded_read32_park(void)
{
    ++parks; CHECK(expected_park); longjmp(escape,1);
}
int stage90_guarded_read32_load_arm(uint32_t address,uint32_t *sample)
{
    uint32_t frame[6]; ++leaves;
    CHECK(stage90_guarded_read32_state.active==1);
    CHECK((post & 0x80u)!=0 && ((post^pre)&0x140u)==0);
    CHECK(stage90_guarded_read32_state.cpsr_before_mask==pre);
    CHECK(stage90_guarded_read32_state.cpsr_after_mask==post);
    if(behavior==0) { *sample=value; return 0; }
    if(behavior==4) {
        struct stage90_guarded_read32_state before=stage90_guarded_read32_state, after;
        CHECK(stage90_guarded_read32(address,sample)==STAGE90_GUARDED_BUSY);
        after=stage90_guarded_read32_state; CHECK(memcmp(&before,&after,sizeof before)==0);
        *sample=value; return 0;
    }
    frame_init(frame); if(behavior==2) frame[5]+=4;
    enum stage90_guarded_abort_result r=stage90_guarded_read32_abort_policy(
        &stage90_guarded_read32_state,frame,behavior==3 ? fs(0x16):5,address,post);
    if(r!=STAGE90_GUARDED_RECOVERED) stage90_guarded_read32_park();
    CHECK(frame[5]==rpc());
    if(behavior==5) { *sample=value; return 0; } /* broken leaf must not succeed */
    return STAGE90_GUARDED_FAULT;
}
static void reset(void)
{
    stage90_guarded_read32_state=(struct stage90_guarded_read32_state){0};
    leaves=saves=restores=parks=0; pre=post=0x13u; mask_xor=0; value=0xaabbccddu;
    behavior=expected_park=0;
}
static void policy_tests(void)
{
    for(unsigned f=0;f<=0x40;f+=0x40) for(unsigned c=0;c<32;++c)
    for(unsigned write=0;write<2;++write) for(unsigned domain=0;domain<16;++domain) {
        CASE(); struct stage90_guarded_read32_state s=armed(f);
        uint32_t frame[6],before[6]; frame_init(frame); memcpy(before,frame,sizeof frame);
        uint32_t dfsr=fs(c)|(domain<<4)|(write<<11); int yes=documented(c)&&!write;
        CHECK(stage90_guarded_read32_abort_policy(&s,frame,dfsr,s.expected_address,0x93u|f)==
              (yes?STAGE90_GUARDED_RECOVERED:STAGE90_GUARDED_UNSUPPORTED));
        CHECK(frame[5]==(yes?rpc():fpc())); CHECK(memcmp(frame,before,5*sizeof(uint32_t))==0);
        CHECK(s.active==1 && s.fault_count==1); CHECK(s.fault_dfsr==dfsr && s.fault_dfar==s.expected_address);
        CHECK(s.cpsr_before_mask==(0x13u|f) && s.cpsr_after_mask==(0x93u|f));
    }
    for(unsigned f=0;f<=0x40;f+=0x40) {
        /* Every SPSR stable bit rejects if different; NZCV (all 16 combinations) ignored. */
        for(unsigned bit=0;bit<32;++bit) if((1u<<bit)&STAGE90_GUARD_STABLE_CPSR) {
            CASE(); struct stage90_guarded_read32_state s=armed(f); uint32_t p[6]; frame_init(p);
            CHECK(stage90_guarded_read32_abort_policy(&s,p,5,s.expected_address,(0x93u|f)^(1u<<bit))==STAGE90_GUARDED_UNSUPPORTED);
            CHECK(p[5]==fpc() && s.status==7 && s.active==1);
        }
        for(unsigned flags=0;flags<16;++flags) {
            CASE(); struct stage90_guarded_read32_state s=armed(f); uint32_t p[6]; frame_init(p);
            CHECK(stage90_guarded_read32_abort_policy(&s,p,5,s.expected_address,(0x93u|f)|(flags<<28))==STAGE90_GUARDED_RECOVERED);
        }
        for(unsigned mutation=0;mutation<18;++mutation) {
            CASE(); struct stage90_guarded_read32_state s=armed(f); uint32_t p[6]; frame_init(p);
            uint32_t dfsr=5,dfar=s.expected_address;
            switch(mutation) {
            case 0:p[5]+=4;break; case 1:dfar+=4;break; case 2:s.active=2;break;
            case 3:s.expected_address|=1;dfar=s.expected_address;break;
            case 4:s.fault_pc+=4;p[5]=s.fault_pc;break; case 5:s.recovery_pc+=4;break;
            case 6:s.status=2;break;case 7:s.fault_count=1;break;
            case 8:s.cpsr_before_mask^=0x40;break;case 9:s.cpsr_after_mask^=0x40;break;
            case 10:s.cpsr_after_mask&=~0x80u;break;case 11:s.cpsr_before_mask^=0x100;break;
            case 12:dfsr|=0x200;break;case 13:dfsr|=0x10000;break;case 14:dfsr|=0x2000;break;
            case 15:dfsr|=0x100;break;case 16:dfsr|=0x4000;break;case 17:s.cpsr_before_mask^=0x20;break;
            }
            uint32_t pc=p[5]; CHECK(stage90_guarded_read32_abort_policy(&s,p,dfsr,dfar,0x93u|f)==STAGE90_GUARDED_UNSUPPORTED);
            CHECK(p[5]==pc && s.status==7 && s.breadcrumb==0x47524458u);
        }
        CASE(); struct stage90_guarded_read32_state s=armed(f),snap; uint32_t p[6],p0[6];
        frame_init(p);memcpy(p0,p,sizeof p);s.active=0;snap=s;
        CHECK(stage90_guarded_read32_abort_policy(&s,p,~0u,0,0)==STAGE90_GUARDED_NOT_HANDLED);
        CHECK(memcmp(&s,&snap,sizeof s)==0 && memcmp(p,p0,sizeof p)==0);
        CASE();s=armed(f);CHECK(stage90_guarded_read32_abort_policy(&s,0,5,s.expected_address,0x93u|f)==STAGE90_GUARDED_UNSUPPORTED);
        CASE();s=armed(f);frame_init(p);CHECK(stage90_guarded_read32_abort_policy(&s,p,0x1008,s.expected_address,0x93u|f)==STAGE90_GUARDED_RECOVERED);
        p[5]=fpc();CHECK(stage90_guarded_read32_abort_policy(&s,p,8,s.expected_address,0x93u|f)==STAGE90_GUARDED_UNSUPPORTED);
    }
}
static void wrapper_tests(void)
{
    static uint32_t out;
    for(unsigned f=0;f<=0x40;f+=0x40) for(unsigned a=0;a<=0x100;a+=0x100)
    for(unsigned i=0;i<=0x80;i+=0x80) for(unsigned fault=0;fault<2;++fault) {
        CASE();reset();pre=post=0x13u|f|a|i;behavior=(int)fault;out=0x12345678;
        CHECK(stage90_guarded_read32(0xf9000100,&out)==(fault?2:0));
        CHECK(out==(fault?0x12345678:value));CHECK(leaves==1&&restores==1&&parks==0);
        CHECK(stage90_guarded_read32_state.active==0&&stage90_guarded_read32_state.fault_count==fault);
        CHECK(post==pre); CHECK(stage90_guarded_read32_state.cpsr_after_mask==(pre|0x80));
    }
    for(unsigned f=0;f<=0x40;f+=0x40) for(unsigned b=0;b<32;++b)
    if(((1u<<b)&(STAGE90_GUARD_STABLE_CPSR|0x100u))!=0) {
        CASE();reset();pre=post=0x13u|f;mask_xor=1u<<b;out=9;
        CHECK(stage90_guarded_read32(0xf9000100,&out)==STAGE90_GUARDED_BAD_CONTEXT);
        CHECK(leaves==0&&out==9&&restores==1&&stage90_guarded_read32_state.active==0);
        CHECK(stage90_guarded_read32_state.status==6);
    }
    CASE();reset();CHECK(stage90_guarded_read32(0xf9000100,0)==4&&saves==0&&leaves==0);
    CASE();reset();out=9;CHECK(stage90_guarded_read32(0xf9000101,&out)==4&&out==9&&leaves==0);
    CASE();reset();pre=post=0x10;out=9;CHECK(stage90_guarded_read32(0xf9000100,&out)==6&&leaves==0&&restores==0);
    CASE();reset();behavior=4;CHECK(stage90_guarded_read32(0xf9000100,&out)==0&&restores==2);
    CASE();reset();stage90_guarded_read32_state.active=2;out=9;
    struct stage90_guarded_read32_state before=stage90_guarded_read32_state,after;
    CHECK(stage90_guarded_read32(0xf9000100,&out)==5&&out==9&&leaves==0);
    after=stage90_guarded_read32_state;CHECK(memcmp(&before,&after,sizeof before)==0);
    for(int b=2;b<=5;++b) if(b!=4) {
        CASE();reset();behavior=b;expected_park=1;out=9;
        if(setjmp(escape)==0) { (void)stage90_guarded_read32(0xf9000100,&out);CHECK(0); }
        CHECK(out==9&&parks==1&&restores==0&&stage90_guarded_read32_state.active==1);
        CHECK(stage90_guarded_read32_state.status==7);
    }
}
int main(void)
{
    policy_tests();wrapper_tests();
    printf("PASS future actual C: %u cases, %u assertions; fake leaf, NOT FIQ runtime\n",cases,checks);
    return 0;
}
