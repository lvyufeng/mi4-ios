#!/usr/bin/env python3
"""Host-only actual-C probe regression; no firmware build or hardware access.

Copy the entire probe and production identify core/header to a fresh temporary
folder, replacing ONLY its six CPU-register reads with fake assignments. Each
case runs in a fresh process, preserving the actual function-local one-shot.
The guarded-load implementation, ARM exception handling and bus completion are
not tested here. No production tool is imported, and no repository file is changed.
"""
import argparse
import hashlib
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

STUB = '''#ifndef TEST_STAGE90_H
#define TEST_STAGE90_H
#include <stdint.h>
#include <stddef.h>
#define STAGE90_PMAP_DESC_SECTION_SO 0x00010c02u
%s
const struct stage90_hw_watchdog_result *stage90_hw_watchdog_result(void);
uint32_t stage90_deadman_armed(void);
uint32_t *mmu_l1_table(void);
void xnu_log_puts(const char *s);
void xnu_log_kv32(const char *key, uint32_t value);
uint64_t timebase_ticks(void);
uint32_t timebase_elapsed_us(uint64_t start, uint64_t end);
void delay_us(uint32_t usec);
void stage90_dwc3_readonly_probe(void);
#endif
'''
HARNESS = r'''
#include "stage90.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if STAGE90_DWC3_READONLY
#include "dwc3_identify.h"
#include "stage90_guarded_read32.h"
volatile struct stage90_guarded_read32_state stage90_guarded_read32_state;
const unsigned char stage90_guarded_read32_fault[4] __attribute__((aligned(4)))={1,2,3,4};
const unsigned char stage90_guarded_read32_recovery[4] __attribute__((aligned(4)))={5,6,7,8};
static struct stage90_guarded_read32_state ram_evidence, fault_evidence;
static uint32_t saved_f;
static int irq_case=-1;
#if STAGE90_GUARDED_STORE_SELFTEST
const unsigned char stage90_guarded_write32_fault[4] __attribute__((aligned(4)))={9,10,11,12};
static int store_case=-1;
static unsigned store_calls;
static uint32_t store_restored;
#endif
static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"CHECK line %d: %s\n",__LINE__,#x); exit(1); } } while (0)
static uint32_t l1[4096] __attribute__((aligned(16384)));
uint8_t stage90_vectors[32];
static uint32_t fake_cpsr=0x13u, fake_sctlr=1u, fake_vbar, fake_ttbr0, fake_ttbcr, fake_dacr=3u;
static int null_table, null_watchdog, deadman=1, fail=-1, direct, guard_case=-1;
static uint64_t now, step;
static uint32_t en=1u, first=200u, second=220u;
static struct stage90_hw_watchdog_result wd;
static struct effects { unsigned reads, logs, textbytes, mmu, watchdogs, deadmans, delays, ticks; } effects;
static char text[1024];
static struct { const char *key; uint32_t value; } logs[128];
static uint32_t golden[] = {
    0u,0xdeadc000u,0xf9017008u,0xf901700cu,0xf901700cu,
    0xfc400108u,0xfc4003c8u,0xfc4003d0u,0xfc4003ccu,0xfc4004acu,
    0xfc4003c0u,0xfc4003d4u,
#if STAGE90_DWC3_ROOT_SNAPSHOT
    0xfc4003d8u,0xfc4003dcu,0xfc4003e0u,0xfc4003e4u,0xfc40001cu,0xfc401480u
#else
    0xf920c120u,0xf920c110u,0xf920c140u,
    0xf920c144u,0xf920c200u,0xf920c700u,0xf920c704u,0xf920c70cu
#endif
};
static uint32_t values[15] = {1u,1u,1u,1u,1u,0u,2u,0x5533220au,
    0x12340008u,0x12340009u,0x1234000au,0x1234000bu,0x1234000cu,0x1234000du,0x1234000eu};
static uint32_t seen[20];
#if STAGE90_DWC3_ROOT_SNAPSHOT
#define TARGET_COUNT 13u
#elif STAGE90_DWC3_CLOCK_SNAPSHOT
#define TARGET_COUNT 7u
#else
#define TARGET_COUNT 15u
#endif
#include "actual-probe.c"
uint32_t *mmu_l1_table(void) { ++effects.mmu; return null_table ? NULL : l1; }
const struct stage90_hw_watchdog_result *stage90_hw_watchdog_result(void)
{ ++effects.watchdogs; return null_watchdog ? NULL : &wd; }
uint32_t stage90_deadman_armed(void) { ++effects.deadmans; return (uint32_t)deadman; }
uint64_t timebase_ticks(void) { uint64_t result=now; ++effects.ticks; now+=step; return result; }
uint32_t timebase_elapsed_us(uint64_t start, uint64_t end) { CHECK(end>=start); return (uint32_t)(end-start); }
void delay_us(uint32_t usec) { CHECK(usec==500u); ++effects.delays; }
void xnu_log_puts(const char *s)
{
    int n=snprintf(text+effects.textbytes,sizeof(text)-effects.textbytes,"%s",s);
    CHECK(n>=0 && (unsigned)n<sizeof(text)-effects.textbytes); effects.textbytes+=(unsigned)n;
}
void xnu_log_kv32(const char *key, uint32_t value)
{
    static const char *const keys[]={"dwc3_ro_read_index","dwc3_ro_read_address",
        "dwc3_ro_read_result","dwc3_ro_read_value","dwc3_ro_watchdog_read_address",
        "dwc3_ro_watchdog_count_first","dwc3_ro_watchdog_count_second","dwc3_ro_status",
        "dwc3_ro_completed_reads","dwc3_ro_valid_clocks","dwc3_ro_valid_registers",
        "dwc3_ro_failed_slot","dwc3_ro_elapsed_us","dwc3_ro_guard_ram_address",
        "dwc3_ro_guard_fault_address","dwc3_ro_guard_fault_result","dwc3_ro_guard_fault_dfsr",
        "dwc3_ro_guard_fault_dfar","dwc3_ro_guard_fault_pc","dwc3_ro_guard_ram_result",
        "dwc3_ro_guard_cpsr_before","dwc3_ro_guard_cpsr_after","dwc3_ro_guard_fault_spsr",
        "dwc3_ro_guard_fault_count","dwc3_ro_guard_fault_active","dwc3_ro_guard_fault_status",
        "dwc3_ro_guard_fault_output","dwc3_ro_guard_fault_expected_pc",
        "dwc3_ro_guard_fault_cpsr_before","dwc3_ro_guard_fault_cpsr_after",
        "dwc3_ro_bcr_valid","dwc3_ro_root_valid","dwc3_ro_root_extra_valid",
        "dwc3_store_ram_address","dwc3_store_ram_before_result","dwc3_store_ram_before_value",
        "dwc3_store_ram_value","dwc3_store_ram_result","dwc3_store_ram_active","dwc3_store_ram_status",
        "dwc3_store_ram_count","dwc3_store_ram_operation","dwc3_store_ram_cpsr_before",
        "dwc3_store_ram_cpsr_after","dwc3_store_cpsr_restored","dwc3_store_ram_readback_result",
        "dwc3_store_ram_readback_value","dwc3_store_fault_address","dwc3_store_fault_value",
        "dwc3_store_fault_result","dwc3_store_fault_dfsr","dwc3_store_fault_dfar","dwc3_store_fault_pc",
        "dwc3_store_fault_expected_pc","dwc3_store_fault_spsr","dwc3_store_fault_count",
        "dwc3_store_fault_active","dwc3_store_fault_status","dwc3_store_fault_operation",
        "dwc3_store_fault_cpsr_before","dwc3_store_fault_cpsr_after","dwc3_store_fault_cpsr_restored"};
    unsigned i;
    for(i=0;i<sizeof(keys)/sizeof(keys[0]);++i) if(!strcmp(key,keys[i])) break;
    CHECK(i<sizeof(keys)/sizeof(keys[0]) && effects.logs<128u);
    logs[effects.logs].key=keys[i]; logs[effects.logs++].value=value;
}
static void kv(const char *key, uint32_t value)
{
    unsigned i, count=0;
    for(i=0;i<effects.logs;++i) if(!strcmp(logs[i].key,key)) { CHECK(logs[i].value==value); ++count; }
    CHECK(count==1u);
}
int stage90_guarded_read32(uint32_t address, uint32_t *out)
{
    unsigned i=effects.reads++;
    CHECK(i<20u && out!=NULL); seen[i]=address;
    if(direct) {
        CHECK(address==golden[5]);
        if((int)i==fail) return -7;
        *out=1u; return 0;
    }
    if(i==0u) {
        unsigned j;
        CHECK(address!=0u && (address&3u)==0u);
#if STAGE90_DWC3_ROOT_SNAPSHOT
        for(j=1u;j<sizeof(golden)/sizeof(golden[0]);++j) CHECK(address!=golden[j]);
#else
        for(j=1u;j<20u;++j) CHECK(address!=golden[j]);
#endif
        CHECK(effects.logs>0u && !strcmp(logs[effects.logs-1u].key,"dwc3_ro_guard_ram_address"));
        CHECK(logs[effects.logs-1u].value==address && *out==0xa55a12edu);
        golden[0]=address;
        ram_evidence=(struct stage90_guarded_read32_state){0};
        ram_evidence.cpsr_before_mask=0x13u|saved_f;
        ram_evidence.cpsr_after_mask=ram_evidence.cpsr_before_mask|
            (STAGE90_GUARDED_IRQ_ONLY ? 0x80u : 0xc0u);
        ram_evidence.status=guard_case==1 ? STAGE90_GUARDED_FAULT : STAGE90_GUARDED_OK;
        if(guard_case>=16) {
            static const uint32_t missing[]={0x40u,0x80u,0xc0u};
            ram_evidence.cpsr_after_mask &= ~missing[guard_case-16];
            ram_evidence.status=STAGE90_GUARDED_BAD_CONTEXT;
        }
        stage90_guarded_read32_state=ram_evidence;
        if(guard_case>=16) return STAGE90_GUARDED_BAD_CONTEXT;
        if(guard_case==1) return -7;
        *out=guard_case==2 ? 0x47524451u : 0x47524450u;
        return 0;
    }
#if STAGE90_GUARDED_STORE_SELFTEST
    if(i>=2u) {
        CHECK(i<4u && address==(uint32_t)(uintptr_t)&dwc3_probe_store_word && *out==0u);
        stage90_guarded_read32_state=(struct stage90_guarded_read32_state){0};
        if((i==2u && store_case==0) || (i==3u && store_case==3)) return -7;
        *out=dwc3_probe_store_word;
        if((i==2u && store_case==1) || (i==3u && store_case==4)) *out^=1u;
        return 0;
    }
#endif
    CHECK(address==golden[i]);
#if STAGE90_DWC3_ROOT_SNAPSHOT
    if(i>=5u) CHECK(i<18u && address>=0xfc400000u && address<0xfc402000u);
#elif STAGE90_DWC3_CLOCK_SNAPSHOT
    if(i>=5u) CHECK(i<12u && address>=0xfc400000u && address<0xfc401000u);
#endif
    if(i==1u) {
        struct stage90_guarded_read32_state state={0};
        CHECK(*out==0xa55a12edu);
        state.expected_address=address; state.status=STAGE90_GUARDED_FAULT; state.fault_count=1u;
        state.fault_dfar=address; state.fault_dfsr=5u;
        state.fault_pc=state.observed_pc=(uint32_t)(uintptr_t)stage90_guarded_read32_fault;
        state.recovery_pc=(uint32_t)(uintptr_t)stage90_guarded_read32_recovery;
        state.cpsr_before_mask=0x13u|saved_f;
        state.cpsr_after_mask=state.cpsr_before_mask|(STAGE90_GUARDED_IRQ_ONLY ? 0x80u : 0xc0u);
        state.observed_spsr=state.cpsr_after_mask;
        if(irq_case>=0) {
            static const unsigned bits[]={7u,6u,0u,5u,9u,24u};
            CHECK(STAGE90_GUARDED_IRQ_ONLY && irq_case<16);
            if(irq_case<6) state.observed_spsr^=1u<<bits[irq_case];
            else if(irq_case<11) {
                static const unsigned post_bits[]={7u,0u,5u,9u,24u};
                state.cpsr_after_mask^=1u<<post_bits[irq_case-6];
            } else if(irq_case<13) state.cpsr_before_mask^=irq_case==11 ? 0x100u : 0x40u;
            else if(irq_case==13) state.observed_spsr^=0xf8000000u; /* NZCV/Q ignored. */
            else if(irq_case==14) state.observed_spsr^=0x100u; /* Saved A is not stable-mask data. */
            else state.cpsr_before_mask|=0xf0000000u; /* Flag transitions are permitted. */
        }
        switch(guard_case) {
        case 4:*out=0xdeadbeefu;break; case 5:state.status=STAGE90_GUARDED_OK;break;
        case 6:state.fault_count=0u;break; case 7:state.fault_count=2u;break;
        case 8:state.active=1u;break; case 9:state.expected_address^=4u;break;
        case 10:state.fault_dfar^=4u;break; case 11:state.fault_dfsr=0u;break;
        case 12:state.fault_dfsr=7u;break; case 13:state.fault_dfsr=0x405u;break;
        case 14:state.observed_pc+=4u;break;
        }
        fault_evidence=state; stage90_guarded_read32_state=state;
        return guard_case==3 ? 0 : guard_case==15 ? -7 : STAGE90_GUARDED_FAULT;
    }
    CHECK(*out==0u); /* Ordinary failed reads never poison or write the output. */
    stage90_guarded_read32_state=(struct stage90_guarded_read32_state){0};
    if((int)i==fail) return -7;
    *out=i==2u ? en : i==3u ? first : i==4u ? second : values[i-5u];
    return 0;
}
#if STAGE90_GUARDED_STORE_SELFTEST
uint32_t stage90_guarded_read32_cpsr_read(void) { return store_restored; }
int stage90_guarded_write32(uint32_t address, uint32_t value)
{
    struct stage90_guarded_read32_state state={0};
    unsigned call=store_calls++;
    CHECK(call<2u);
    CHECK(address==(call==0u ? (uint32_t)(uintptr_t)&dwc3_probe_store_word : 0xdeadc000u));
    CHECK(value==(call==0u ? 0x53545231u : 0xfeed1234u));
    state.expected_address=address;state.operation=1u;
    state.cpsr_before_mask=0x13u|saved_f;state.cpsr_after_mask=state.cpsr_before_mask|0x80u;
    store_restored=state.cpsr_before_mask;
    if(call==0u) {
        CHECK(effects.reads==3u && dwc3_probe_store_word==0xa55a12edu);
        state.status=STAGE90_GUARDED_OK;
        if(store_case==2) state.status=STAGE90_GUARDED_WRITE_FAULT;
        else dwc3_probe_store_word=value;
        if(store_case==5) state.active=1u;
        if(store_case==6) state.status=STAGE90_GUARDED_FAULT;
        if(store_case==7) state.operation=0u;
        if(store_case==8) state.fault_count=1u;
        if(store_case==9) state.cpsr_after_mask^=0x80u;
        if(store_case==10) state.cpsr_before_mask^=0x40u;
        if(store_case==11) store_restored^=0x80u;
        stage90_guarded_read32_state=state;
        return store_case==2 ? STAGE90_GUARDED_WRITE_FAULT : 0;
    }
    CHECK(effects.reads==4u && dwc3_probe_store_word==0x53545231u);
    state.status=STAGE90_GUARDED_WRITE_FAULT;state.fault_count=1u;
    state.fault_dfsr=0x805u;state.fault_dfar=address;
    state.observed_pc=state.fault_pc=(uint32_t)(uintptr_t)stage90_guarded_write32_fault;
    state.observed_spsr=state.cpsr_after_mask;
    switch(store_case) {
    case 12:state.fault_dfsr=5u;break; case 13:state.fault_dfsr=0x807u;break;
    case 14:state.fault_dfsr=0x2805u;break; case 15:state.fault_dfar^=4u;break;
    case 16:state.observed_pc+=4u;break; case 17:state.observed_spsr^=0x80u;break;
    case 18:state.fault_count=0u;break; case 19:state.fault_count=2u;break;
    case 20:state.active=1u;break; case 21:state.status=STAGE90_GUARDED_OK;break;
    case 22:state.operation=0u;break; case 23:state.cpsr_after_mask^=0x40u;break;
    case 24:store_restored^=0x80u;break; case 25:state.expected_address^=4u;break;
    }
    stage90_guarded_read32_state=state;
    return store_case==26 ? 0 : STAGE90_GUARDED_WRITE_FAULT;
}
#endif
static void callback_checks(void)
{
    struct dwc3_probe_context ctx={0u,0u};
    uint32_t value=0x12345678u;
    static const uint32_t bad[]={0u,0xf9017008u,0xf901700cu,0xfc400109u,0xf920c124u,0xffffffffu};
    unsigned i;
    direct=1;
    for(i=0;i<sizeof(bad)/sizeof(bad[0]);++i) CHECK(dwc3_probe_read(&ctx,bad[i],&value)!=0);
#if STAGE90_DWC3_ROOT_SNAPSHOT
    {
        static const uint32_t core[]={0xf920c120u,0xf920c110u,0xf920c140u,0xf920c144u,
            0xf920c200u,0xf920c700u,0xf920c704u,0xf920c70cu};
        for(i=0;i<8u;++i) CHECK(dwc3_probe_read(&ctx,core[i],&value)!=0);
        CHECK(dwc3_probe_read(&ctx,0xfc400020u,&value)!=0);
    }
#elif STAGE90_DWC3_CLOCK_SNAPSHOT
    for(i=12u;i<20u;++i) CHECK(dwc3_probe_read(&ctx,golden[i],&value)!=0);
    CHECK(dwc3_probe_read(&ctx,0xfc4003d8u,&value)!=0);
#endif
    CHECK(dwc3_probe_read(NULL,golden[5],&value)!=0);
    CHECK(dwc3_probe_read(&ctx,golden[5],NULL)!=0);
    ctx.attempted=TARGET_COUNT; CHECK(dwc3_probe_read(&ctx,golden[5],&value)!=0);
    ctx.attempted=0u; now=10001u; CHECK(dwc3_probe_read(&ctx,golden[5],&value)!=0);
    CHECK(effects.reads==0u && effects.logs==0u && ctx.attempted==0u && value==0x12345678u);
    ctx.attempted=TARGET_COUNT-1u; now=10000u; value=0u;
    CHECK(dwc3_probe_read(&ctx,golden[5],&value)==0);
    CHECK(ctx.attempted==TARGET_COUNT && value==1u && effects.reads==1u);
    CHECK(dwc3_probe_read(&ctx,golden[5],&value)!=0 && effects.reads==1u);
    ctx.attempted=0u; fail=1; value=0xabcdef01u;
    CHECK(dwc3_probe_read(&ctx,golden[5],&value)==-7 && value==0xabcdef01u);
    CHECK(ctx.attempted==1u && effects.reads==2u);
}
#if STAGE90_GUARDED_STORE_SELFTEST
static void store_verify(unsigned expected_reads, unsigned expected_stores, const char *skip)
{
    struct effects saved;
    struct stage90_guarded_read32_state before,after;
    unsigned i,writes=store_calls;
    CHECK(effects.reads==expected_reads && writes==expected_stores && effects.delays==0u);
    CHECK(strstr(text,"DWC3 guarded RAM store selftest; no MMIO target writes")!=NULL);
    CHECK((strstr(text,"dwc3_ro store selftest passed; RAM writes only; controller target reads inhibited")!=NULL)==(skip==NULL));
    CHECK(strstr(text,"dwc3_ro finished;")==NULL && strstr(text,"DWC3 read-only")==NULL);
    if(skip) CHECK(strstr(text,skip)!=NULL);
    for(i=0;i<effects.logs;++i) {
        CHECK(strncmp(logs[i].key,"dwc3_ro_read_",13)!=0);
        CHECK(strncmp(logs[i].key,"dwc3_ro_watchdog_",17)!=0);
        CHECK(strcmp(logs[i].key,"dwc3_ro_status")!=0);
    }
    if(expected_reads>2u) {
        kv("dwc3_store_ram_address",(uint32_t)(uintptr_t)&dwc3_probe_store_word);
        kv("dwc3_store_ram_before_result",store_case==0 ? (uint32_t)-7 : 0u);
    }
    if(writes>0u) {
        kv("dwc3_store_ram_value",0x53545231u);
        kv("dwc3_store_ram_result",store_case==2 ? STAGE90_GUARDED_WRITE_FAULT : 0u);
    }
    if(!skip) {
        kv("dwc3_store_ram_before_value",0xa55a12edu);
        kv("dwc3_store_ram_readback_result",0u);kv("dwc3_store_ram_readback_value",0x53545231u);
        kv("dwc3_store_ram_operation",1u);kv("dwc3_store_ram_status",STAGE90_GUARDED_OK);
        kv("dwc3_store_ram_active",0u);kv("dwc3_store_ram_count",0u);
        kv("dwc3_store_cpsr_restored",0x13u|saved_f);
        kv("dwc3_store_fault_address",0xdeadc000u);kv("dwc3_store_fault_value",0xfeed1234u);
        kv("dwc3_store_fault_result",STAGE90_GUARDED_WRITE_FAULT);
        kv("dwc3_store_fault_dfsr",0x805u);kv("dwc3_store_fault_dfar",0xdeadc000u);
        kv("dwc3_store_fault_pc",(uint32_t)(uintptr_t)stage90_guarded_write32_fault);
        kv("dwc3_store_fault_expected_pc",(uint32_t)(uintptr_t)stage90_guarded_write32_fault);
        kv("dwc3_store_fault_spsr",0x93u|saved_f);
        kv("dwc3_store_fault_status",STAGE90_GUARDED_WRITE_FAULT);kv("dwc3_store_fault_count",1u);
        kv("dwc3_store_fault_active",0u);kv("dwc3_store_fault_operation",1u);
        kv("dwc3_store_fault_cpsr_restored",0x13u|saved_f);
    }
    saved=effects;before=stage90_guarded_read32_state;
    stage90_dwc3_readonly_probe();after=stage90_guarded_read32_state;
    CHECK(!memcmp(&saved,&effects,sizeof(saved)) && !memcmp(&before,&after,sizeof(after)) && writes==store_calls);
}
#endif
int main(int argc, char **argv)
{
    const char *name;
    unsigned p, expected=TARGET_COUNT+5u, completed=TARGET_COUNT, slot=UINT32_MAX, status=MI4_DWC3_IDENTIFY_OK;
    unsigned clocks=31u, regs=STAGE90_DWC3_CLOCK_SNAPSHOT ? 0u : 255u;
    unsigned summary=1u, delays=1u, i, read_logs=0u, value_logs=0u;
    const char *skip=NULL;
    struct effects saved;
    struct stage90_guarded_read32_state saved_state, after;
    CHECK(argc==3); name=argv[1]; p=(unsigned)strtoul(argv[2],NULL,10);
    fake_vbar=(uint32_t)(uintptr_t)stage90_vectors; fake_ttbr0=(uint32_t)(uintptr_t)l1;
    CHECK((fake_ttbr0 & 0x3fffu)==0u && sizeof(l1)==16384u);
    l1[0xf92]=0xf9200000u|STAGE90_PMAP_DESC_SECTION_SO;
    l1[0xfc4]=0xfc400000u|STAGE90_PMAP_DESC_SECTION_SO;
    wd.enabled=wd.counter_running=wd.countdown_plausible=wd.readback_ok=1u; wd.bark_ticks=100000u;
    if(!strcmp(name,"callback")) { callback_checks(); printf("PASS %u\n",checks); return 0; }
#if STAGE90_GUARDED_STORE_SELFTEST
    wd.countdown_first=100u;wd.countdown_second=110u;
    if(!strcmp(name,"store")) {
        CHECK(p<27u);store_case=(int)p;
        skip=p<12u ? "guard STORE RAM selftest failed" : "guard STORE translation-fault selftest failed";
    } else if(!strcmp(name,"store-headroom")) {
        CHECK(p<3u);
        if(p==0u) wd.countdown_second=wd.countdown_first;
        else if(p==1u) wd.countdown_second=wd.bark_ticks;
        else wd.bark_ticks=wd.countdown_second+65529u;
        skip="recovery net not confirmed";
    } else
#endif
    if(!strcmp(name,"fiq")) {
        CHECK(p<2u); saved_f=p ? 0x40u : 0u; fake_cpsr|=saved_f;
    } else if(!strcmp(name,"irq-state")) {
        CHECK(STAGE90_GUARDED_IRQ_ONLY && p<16u); irq_case=(int)p;
        if(p<13u) { expected=2u;summary=delays=0u;skip="guard translation-fault selftest failed"; }
    } else if(!strcmp(name,"cpu")) {
        static const unsigned cpsr_bits[]={0,1,2,3,4,5,9,24}, sctlr_bits[]={0,2,13,25,28,30};
        CHECK(p<14u); if(p<8u) fake_cpsr^=1u<<cpsr_bits[p]; else fake_sctlr^=1u<<sctlr_bits[p-8u];
        skip="CPU/MMU/vector precondition";
    } else if(!strcmp(name,"precondition")) {
        CHECK(p<8u);
        switch(p) { case 0:fake_ttbcr=1u;break; case 1:fake_vbar^=4u;break;
        case 2:fake_ttbr0^=0x4000u;break; case 3:case 4:case 5:fake_dacr=p-3u;break;
        case 6:null_table=1;break; case 7:fake_cpsr=0x12u;break; }
        skip="CPU/MMU/vector precondition";
    } else if(!strcmp(name,"mapping")) {
        CHECK(p<4u); l1[p<2u ? 0xf92 : 0xfc4]=p%2u ? 0xf9200c02u : 0u;
        skip="identity MMIO mapping mismatch";
    } else if(!strcmp(name,"watchdog")) {
        CHECK(p<7u);
        switch(p) { case 0:null_watchdog=1;break; case 1:wd.enabled=0u;break;
        case 2:wd.counter_running=0u;break; case 3:wd.countdown_plausible=0u;break;
        case 4:wd.readback_ok=0u;break; case 5:wd.bite_truncated=1u;break; case 6:deadman=0;break; }
        skip="recovery net not confirmed";
    } else if(!strcmp(name,"selftest")) {
        CHECK(p<19u); guard_case=(int)p; summary=delays=0u;
        if(p==0u) { l1[0xdea]=1u;expected=0u;skip="guard selftest address is mapped"; }
        else if(p<3u || p>=16u) { expected=1u;skip="guard RAM selftest failed"; }
        else { expected=2u;skip="guard translation-fault selftest failed"; }
    } else if(!strcmp(name,"fault")) {
        CHECK(p<TARGET_COUNT+3u); fail=(int)p+2; expected=p+3u;
        if(p<3u) { summary=0u; delays=p==2u; } else {
            slot=p-3u; completed=slot; status=MI4_DWC3_IDENTIFY_READ_FAILED;
            clocks=(1u<<(slot<5u ? slot : 5u))-1u;
            regs=!STAGE90_DWC3_CLOCK_SNAPSHOT && slot>7u ? (1u<<(slot-7u))-1u : 0u;
        }
    } else if(!strcmp(name,"en-off")) { en=0u; expected=3u; summary=delays=0u; }
    else if(!strcmp(name,"counter")) {
        CHECK(p<7u);
        switch(p) { case 0:second=first;break; case 1:second=first-2u;break;
        case 2:wd.bark_ticks=110u;break; case 3:wd.bark_ticks=109u;break;
        case 4:wd.bark_ticks=110u+65529u;break; case 5:wd.bark_ticks=110u+65530u;break;
        case 6:first|=0xffe00001u;second|=0xffe00001u;break; }
        if(p<5u) { expected=5u;summary=0u; }
    } else if(!strcmp(name,"clock") || !strcmp(name,"clock-state")) {
        unsigned index=0u, value;
        if(!strcmp(name,"clock")) { CHECK(p<5u);index=p;value=0x10000001u; }
        else { CHECK(p<32u);value=(p/2u<<28)|(p%2u); }
        values[index]=value;
        if(!STAGE90_DWC3_CLOCK_SNAPSHOT &&
           (!(value&1u) || ((value>>28)!=0u && (value>>28)!=2u))) {
            completed=index+1u;expected=completed+5u;clocks=(1u<<completed)-1u;regs=0u;
            status=MI4_DWC3_IDENTIFY_CLOCK_BLOCKED;
        }
    } else if(!strcmp(name,"reset")) {
        values[5]=1u;
        if(!STAGE90_DWC3_CLOCK_SNAPSHOT) {
            completed=6u;expected=11u;regs=0u;status=MI4_DWC3_IDENTIFY_RESET_ASSERTED;
        }
    } else if(!strcmp(name,"root")) {
        static const uint32_t bad[]={0u,1u,3u,0x80000002u,0x12u,0x22u,0x42u,0x82u};
        CHECK(p<8u);values[6]=bad[p];
        if(!STAGE90_DWC3_CLOCK_SNAPSHOT) {
            completed=7u;expected=12u;regs=0u;status=MI4_DWC3_IDENTIFY_ROOT_BLOCKED;
        }
    } else if(!strcmp(name,"snapshot-disabled")) {
        CHECK(STAGE90_DWC3_CLOCK_SNAPSHOT);
        values[0]=0x80000000u;values[5]=1u;values[6]=0x800000f3u;
    } else if(!strcmp(name,"root-extra")) {
        CHECK(STAGE90_DWC3_ROOT_SNAPSHOT && p<6u);values[p+7u]=0xffffffffu;
    } else if(!strcmp(name,"id")) {
        values[7]=0x55320000u;completed=8u;expected=13u;regs=1u;status=MI4_DWC3_IDENTIFY_WRONG_ID;
    } else if(!strcmp(name,"snapshot-budget")) {
        CHECK(STAGE90_DWC3_CLOCK_SNAPSHOT && p<TARGET_COUNT);
        step=10000u/(p+1u)+1u;expected=5u+p;completed=p;slot=p;
        clocks=(1u<<(p<5u ? p : 5u))-1u;regs=0u;status=MI4_DWC3_IDENTIFY_READ_FAILED;
    } else if(!strcmp(name,"deadline")) {
        step=10001u;expected=5u;completed=clocks=regs=0u;slot=0u;status=MI4_DWC3_IDENTIFY_READ_FAILED;
    } else CHECK(!strcmp(name,"golden"));
    if(skip && guard_case<0 && irq_case<0) { expected=summary=delays=0u; }
#if !STAGE90_DWC3_TARGET_READS
    if(!skip) { expected=2u;summary=delays=0u; }
#endif
#if STAGE90_GUARDED_STORE_SELFTEST
    {
        unsigned stores=0u,reads=expected;
        if(!strcmp(name,"store")) {
            reads=store_case<2 ? 3u : store_case==2 || (store_case>=5 && store_case<12) ? 3u : 4u;
            stores=store_case<2 ? 0u : store_case<12 ? 1u : 2u;
        } else if(!skip) { reads=4u;stores=2u; }
        stage90_dwc3_readonly_probe();store_verify(reads,stores,skip);
        printf("PASS %u\n",checks);return 0;
    }
#endif
    stage90_dwc3_readonly_probe();
    CHECK(effects.reads==expected && effects.delays==delays);
    for(i=0;i<expected;++i) CHECK(seen[i]==golden[i]);
#if STAGE90_DWC3_ROOT_SNAPSHOT
    CHECK(strstr(text,"DWC3 read-only GCC root snapshot; no DWC3 core reads")!=NULL);
    CHECK(strstr(text,"DWC3 read-only identity probe;")==NULL);
    CHECK((strstr(text,"dwc3_ro finished; GCC root snapshot only; no DWC3 core reads")!=NULL)==summary);
    CHECK(strstr(text,"GCC clock snapshot")==NULL && strstr(text,"identification is not a USB link")==NULL);
#elif STAGE90_DWC3_CLOCK_SNAPSHOT
    CHECK(strstr(text,"DWC3 read-only GCC clock snapshot; no DWC3 core reads")!=NULL);
    CHECK(strstr(text,"DWC3 read-only identity probe;")==NULL);
    CHECK((strstr(text,"dwc3_ro finished; GCC clock snapshot only; no DWC3 core reads")!=NULL)==summary);
    CHECK(strstr(text,"identification is not a USB link")==NULL);
#else
    CHECK(strstr(text,"DWC3 read-only identity probe;")!=NULL);
#endif
    if(skip) CHECK(strstr(text,skip)!=NULL);
    CHECK((strstr(text,"dwc3_ro finished;")!=NULL)==summary);
    CHECK((strstr(text,"guard selftest passed:")!=NULL)==(!skip && expected>=2u));
    CHECK((strstr(text,"controller target reads inhibited")!=NULL)==(!STAGE90_DWC3_TARGET_READS && !skip));
    if(expected>0u) {
        kv("dwc3_ro_guard_ram_address",golden[0]);
        kv("dwc3_ro_guard_ram_result",guard_case>=16 ? STAGE90_GUARDED_BAD_CONTEXT : guard_case==1 ? (uint32_t)-7 : 0u);
        kv("dwc3_ro_guard_cpsr_before",ram_evidence.cpsr_before_mask);
        kv("dwc3_ro_guard_cpsr_after",ram_evidence.cpsr_after_mask);
    }
    if(expected>1u) {
        kv("dwc3_ro_guard_fault_address",0xdeadc000u);
        kv("dwc3_ro_guard_fault_result",guard_case==3 ? 0u : guard_case==15 ? (uint32_t)-7 : STAGE90_GUARDED_FAULT);
        kv("dwc3_ro_guard_fault_dfsr",fault_evidence.fault_dfsr);
        kv("dwc3_ro_guard_fault_dfar",fault_evidence.fault_dfar);
        kv("dwc3_ro_guard_fault_pc",fault_evidence.observed_pc);
        kv("dwc3_ro_guard_fault_spsr",fault_evidence.observed_spsr);
        kv("dwc3_ro_guard_fault_count",fault_evidence.fault_count);
        kv("dwc3_ro_guard_fault_active",fault_evidence.active);
        kv("dwc3_ro_guard_fault_status",fault_evidence.status);
        kv("dwc3_ro_guard_fault_output",guard_case==4 ? 0xdeadbeefu : 0xa55a12edu);
        kv("dwc3_ro_guard_fault_expected_pc",(uint32_t)(uintptr_t)stage90_guarded_read32_fault);
        kv("dwc3_ro_guard_fault_cpsr_before",fault_evidence.cpsr_before_mask);
        kv("dwc3_ro_guard_fault_cpsr_after",fault_evidence.cpsr_after_mask);
    }
    for(i=0;i<effects.logs;++i) {
        if(!strcmp(logs[i].key,"dwc3_ro_read_index")) CHECK(logs[i].value==++read_logs);
        if(!strcmp(logs[i].key,"dwc3_ro_read_address")) {
            CHECK(read_logs>0u && read_logs<=TARGET_COUNT && logs[i].value==golden[read_logs+4u]);
        }
        if(!strcmp(logs[i].key,"dwc3_ro_read_value")) {
            CHECK(read_logs>0u && logs[i].value==values[read_logs-1u]); ++value_logs;
        }
        if(!strcmp(logs[i].key,"dwc3_ro_status")) CHECK(summary);
    }
    CHECK(read_logs==(expected>5u ? expected-5u : 0u));
    CHECK(value_logs==read_logs-(fail>=5 ? 1u : 0u));
    if(summary) {
        kv("dwc3_ro_status",status);kv("dwc3_ro_completed_reads",completed);
        kv("dwc3_ro_valid_clocks",clocks);kv("dwc3_ro_valid_registers",regs);kv("dwc3_ro_failed_slot",slot);
#if STAGE90_DWC3_CLOCK_SNAPSHOT
        kv("dwc3_ro_bcr_valid",completed>5u);kv("dwc3_ro_root_valid",completed>6u);
        CHECK(regs==0u && completed<=TARGET_COUNT);
#endif
#if STAGE90_DWC3_ROOT_SNAPSHOT
        kv("dwc3_ro_root_extra_valid",completed>7u ? (1u<<(completed-7u))-1u : 0u);
#endif
        kv("dwc3_ro_watchdog_count_first",100u);kv("dwc3_ro_watchdog_count_second",110u);
    }
    saved=effects; saved_state=stage90_guarded_read32_state;
    stage90_dwc3_readonly_probe(); after=stage90_guarded_read32_state;
    CHECK(!memcmp(&saved,&effects,sizeof(saved)) && !memcmp(&saved_state,&after,sizeof(after)));
    printf("PASS %u\n",checks); return 0;
}
#else
#include "actual-probe.c"
int main(void) { stage90_dwc3_readonly_probe();stage90_dwc3_readonly_probe();puts("PASS 2");return 0; }
#endif
'''


def clean(text):
    return re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S)


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('missing/ambiguous source seam: '+old)
    return source.replace(old, new, 1)


def cpu_fixture(source):
    instructions = [('cpsr', 'mrs %0, cpsr'), ('sctlr', 'mrc p15, 0, %0, c1, c0, 0'),
                    ('vbar', 'mrc p15, 0, %0, c12, c0, 0'), ('ttbr0', 'mrc p15, 0, %0, c2, c0, 0'),
                    ('ttbcr', 'mrc p15, 0, %0, c2, c0, 2'), ('dacr', 'mrc p15, 0, %0, c3, c0, 0')]
    if len(re.findall(r'\b__asm__\b', clean(source))) != 6:
        raise ValueError('expected exactly six CPU-register reads')
    for name, instruction in instructions:
        source = replace_once(source, '__asm__ volatile("'+instruction+'" : "=r"('+name+'));',
                              name+' = fake_'+name+';')
    if re.search(r'\b(?:__asm__|__asm|asm|volatile|readl|writel)\b', clean(source)):
        raise ValueError('extra assembly or raw volatile MMIO is not permitted')
    return source


def stage90_stub(header):
    structs = re.findall(r'struct stage90_hw_watchdog_result\s*\{[^}]*\};', header, re.S)
    expected = ('enabled timeout_s base sts_before en_before bark_ticks bite_ticks en_after '
                'bark_after bite_after countdown_first countdown_second counter_running '
                'countdown_plausible bite_truncated max_ticks readback_ok checksum').split()
    if len(structs) != 1 or re.findall(r'uint32_t\s+(\w+)\s*;', clean(structs[0])) != expected:
        raise ValueError('actual watchdog layout differs from reviewed baseline')
    if not re.search(r'^#define\s+STAGE90_PMAP_DESC_SECTION_SO\s+0x00010c02u\b', header, re.M):
        raise ValueError('actual strongly-ordered section descriptor changed')
    return STUB % structs[0]


def command(argv):
    return subprocess.run(argv, capture_output=True, text=True, timeout=30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--cc', default='cc', help='compiler command, including optional flags')
    parser.add_argument('--sanitize', action='store_true', help='enable host ASan and UBSan')
    args = parser.parse_args(); root = args.repo_root.resolve(); cc = shlex.split(args.cc)
    if not cc: raise ValueError('empty compiler command')
    names = ['dwc3_probe.c', 'dwc3_identify.c', 'dwc3_identify.h', 'stage90.h',
             'stage90_guarded_read32.h', 'stage90_guarded_profile.h']
    files = [root/'src'/name for name in names]; snapshots = [p.read_bytes() for p in files]
    source = cpu_fixture(snapshots[0].decode())
    cases = [('golden', 0), ('callback', 0), ('en-off', 0), ('reset', 0), ('id', 0), ('deadline', 0)]
    for name, count in [('cpu',14), ('precondition',8), ('mapping',4), ('watchdog',7),
                        ('fault',18), ('selftest',19), ('counter',7), ('clock',5), ('clock-state',32), ('root',8)]:
        cases.extend((name, i) for i in range(count))
    with tempfile.TemporaryDirectory(prefix='mi4-dwc3-probe-') as tmp:
        directory = Path(tmp)
        for name, content in [('stage90.h', stage90_stub(snapshots[3].decode())),
                              ('stage90_guarded_read32.h', snapshots[4].decode()),
                              ('stage90_guarded_profile.h', snapshots[5].decode()), ('harness.c', HARNESS),
                              ('dwc3_identify.c', snapshots[1].decode()), ('dwc3_identify.h', snapshots[2].decode())]:
            (directory/name).write_text(content)
        def build(label, probe, enabled=1, target=1, irq=0, snapshot=0, root_snapshot=0,
                  store32=0, store_selftest=0, compile_error=None):
            (directory/'actual-probe.c').write_text(probe)
            binary = directory/label
            flags = ['-std=c11', '-O0', '-Wall', '-Wextra', '-Werror', '-pedantic',
                     '-DSTAGE90_DWC3_READONLY='+str(enabled),
                     '-DSTAGE90_DWC3_TARGET_READS='+str(target),
                     '-DSTAGE90_DWC3_CLOCK_SNAPSHOT='+str(snapshot),
                     '-DSTAGE90_DWC3_ROOT_SNAPSHOT='+str(root_snapshot),
                     '-DSTAGE90_GUARDED_STORE32='+str(store32),
                     '-DSTAGE90_GUARDED_STORE_SELFTEST='+str(store_selftest),
                     '-DSTAGE90_GUARDED_IRQ_ONLY='+str(irq), '-I', str(directory)]
            if args.sanitize: flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
            result = command(cc+flags+[str(directory/'harness.c'), str(directory/'dwc3_identify.c'), '-o', str(binary)])
            if compile_error is not None:
                if result.returncode == 0 or compile_error not in result.stderr:
                    raise ValueError(label+' failed to reject invalid snapshot mode:\n'+result.stderr)
                return None
            if result.returncode: raise ValueError(label+' compile failed:\n'+result.stderr)
            return binary
        def run(binary, case):
            result = command([str(binary), case[0], str(case[1])])
            if result.returncode: raise ValueError(str(case)+' failed:\n'+result.stdout+result.stderr)
            match = re.fullmatch(r'PASS (\d+)\n', result.stdout)
            if not match: raise ValueError('unexpected harness output: '+result.stdout)
            return int(match[1])
        irq_cases = [('irq-state', i) for i in range(16)]
        fiq_cases = [('fiq', 0), ('fiq', 1)]
        recovery_cases = [('golden', 0)]+fiq_cases+irq_cases
        recovery_cases += [case for case in cases if case[0] in
                           ('cpu', 'precondition', 'mapping', 'watchdog', 'selftest')]
        snapshot_cases = [case for case in cases if case[0]!='id' and
                          (case[0]!='fault' or case[1]<10)]
        snapshot_cases += [('snapshot-disabled',0)]+[('snapshot-budget',i) for i in range(7)]
        root_cases = [case for case in cases if case[0] not in ('id','fault','clock-state')]
        root_cases += [('fault',i) for i in range(16)]
        root_cases += [('snapshot-disabled',0)]+[('snapshot-budget',i) for i in range(13)]
        root_cases += [('root-extra',i) for i in range(6)]
        checks = total = 0
        profiles = [('strict-target', 1, 0, 0, 0, cases+fiq_cases),
                    ('irq-target', 1, 1, 0, 0, cases+fiq_cases+irq_cases),
                    ('irq-recovery-only', 0, 1, 0, 0, recovery_cases),
                    ('irq-clock-snapshot', 1, 1, 1, 0, snapshot_cases+fiq_cases+irq_cases),
                    ('irq-root-snapshot', 1, 1, 1, 1, root_cases+fiq_cases+irq_cases)]
        for label, target, irq, snapshot, root_snapshot, selections in profiles:
            binary = build(label, source, target=target, irq=irq, snapshot=snapshot, root_snapshot=root_snapshot)
            assertions = sum(run(binary, case) for case in selections)
            checks += assertions; total += len(selections)
            print('PASS profile:',label,len(selections),'cases,',assertions,'C assertions')
        # OFF compiles the original, entirely untouched source (no CPU seam needed).
        checks += run(build('actual-off', snapshots[0].decode(), enabled=0, target=0), ('off', 0))
        print('PASS:', total+1, 'fresh-process profile/OFF cases,', checks, 'C assertions')
        store_cases=recovery_cases+[('store',i) for i in range(27)]+[('store-headroom',i) for i in range(3)]
        store_binary=build('irq-store-selftest',source,target=0,irq=1,store32=1,store_selftest=1)
        store_assertions=sum(run(store_binary,case) for case in store_cases)
        print('PASS profile: irq-store-selftest',len(store_cases),'cases,',store_assertions,'C assertions')
        gate = ('if (!watchdog || !watchdog->enabled || !watchdog->counter_running ||\n'
                '        !watchdog->countdown_plausible || !watchdog->readback_ok ||\n'
                '        watchdog->bite_truncated || !stage90_deadman_armed())')
        spsr_check = ('((stage90_guarded_read32_state.observed_spsr ^\n'
                      '             stage90_guarded_read32_state.cpsr_after_mask) & STAGE90_GUARD_STABLE_CPSR)')
        controls = [('watchdog-gate', gate, 'if (!watchdog)', ('watchdog',1), 1, 0, 0),
                    ('address-whitelist', '!dwc3_probe_address_allowed(address)',
                     '(0 && !dwc3_probe_address_allowed(address))', ('callback',0), 1, 0, 0),
                    ('one-shot', 'if (attempted) return;', 'if (attempted > 1u) return;', ('golden',0), 1, 0, 0),
                    ('guard-selftest', 'if (!dwc3_probe_guard_selftest(table)) return;',
                     '(void)dwc3_probe_guard_selftest(table);', ('selftest',5), 1, 0, 0),
                    ('saved-spsr', spsr_check, '0u', ('irq-state',1), 1, 1, 0),
                    ('target-inhibit', '#if !STAGE90_DWC3_TARGET_READS', '#if 0', ('golden',0), 0, 1, 0),
                    ('snapshot-core-whitelist', '#if !STAGE90_DWC3_CLOCK_SNAPSHOT', '#if 1',
                     ('callback',0), 1, 1, 1),
                    ('snapshot-target-cap', 'context->attempted >= 7u ||', 'context->attempted >= 15u ||',
                     ('callback',0), 1, 1, 1),
                    ('snapshot-identity-call', '(void)mi4_dwc3_clock_snapshot(dwc3_probe_read, &context, &identity);',
                     '(void)mi4_dwc3_identify(dwc3_probe_read, &context, &identity);',
                     ('snapshot-disabled',0), 1, 1, 1)]
        for label, old, new, case, target, irq, snapshot in controls:
            binary = build(label, replace_once(source,old,new), target=target, irq=irq, snapshot=snapshot)
            result = command([str(binary),case[0],str(case[1])])
            if result.returncode == 0 or 'CHECK line ' not in result.stderr:
                raise ValueError('negative must fail a C assertion, not compile/crash: '+label+'\n'+result.stderr)
            print('PASS negative:',label,'rejected by actual C behavior')
        for label, old, new, case in (
                ('root-target-cap','context->attempted >= 13u ||','context->attempted >= 15u ||',('callback',0)),
                ('root-core-whitelist','#if !STAGE90_DWC3_CLOCK_SNAPSHOT','#if 1',('callback',0))):
            binary=build(label,replace_once(source,old,new),target=1,irq=1,snapshot=1,root_snapshot=1)
            result=command([str(binary),case[0],str(case[1])])
            if result.returncode==0 or 'CHECK line ' not in result.stderr:
                raise ValueError('root negative must fail a C assertion: '+label+'\n'+result.stderr)
            print('PASS negative:',label,'rejected by actual C behavior')
        store_mutant=replace_once(source,'if (!dwc3_probe_store_selftest(table)) return;',
                                  '(void)dwc3_probe_store_selftest(table);')
        binary=build('store-selftest-bypass',store_mutant,target=0,irq=1,store32=1,store_selftest=1)
        result=command([str(binary),'store','2'])
        if result.returncode==0 or 'CHECK line ' not in result.stderr:
            raise ValueError('store bypass negative must fail C assertion:\n'+result.stderr)
        print('PASS negative: store-selftest-bypass rejected by actual C behavior')
        marker='STAGE90_GUARDED_STORE_SELFTEST_requires_STORE32_IRQ_ONLY_READONLY_and_no_TARGET_READS'
        for label,extra,expected_marker in (
                ('store-selftest-not-bool',{'store_selftest':2},'STAGE90_GUARDED_STORE_SELFTEST_must_be_zero_or_one'),
                ('store-selftest-needs-store',{'store32':0},marker),
                ('store-selftest-forbids-target',{'target':1},marker),
                ('store-selftest-needs-irq',{'irq':0},marker),
                ('store-selftest-needs-readonly',{'enabled':0},marker)):
            options=dict(target=0,irq=1,store32=1,store_selftest=1);options.update(extra)
            build(label,source,compile_error=expected_marker,**options)
            print('PASS invalid mode:',label,'rejected by explicit compile-time contract')
        for label, root_snapshot, snapshot, target, enabled, marker in (
                ('root-not-bool',2,1,1,1,'STAGE90_DWC3_ROOT_SNAPSHOT_must_be_zero_or_one'),
                ('root-requires-clock',1,0,1,1,'STAGE90_DWC3_ROOT_SNAPSHOT_requires_CLOCK_SNAPSHOT_READONLY_and_TARGET_READS'),
                ('root-requires-target',1,1,0,1,'STAGE90_DWC3_ROOT_SNAPSHOT_requires_CLOCK_SNAPSHOT_READONLY_and_TARGET_READS'),
                ('root-requires-readonly',1,1,1,0,'STAGE90_DWC3_ROOT_SNAPSHOT_requires_CLOCK_SNAPSHOT_READONLY_and_TARGET_READS')):
            build(label,source,target=target,enabled=enabled,irq=1,snapshot=snapshot,
                  root_snapshot=root_snapshot,compile_error=marker)
            print('PASS invalid mode:',label,'rejected by explicit compile-time contract')
        for label, enabled, target, snapshot, marker in (
                ('snapshot-not-bool',1,1,2,'STAGE90_DWC3_CLOCK_SNAPSHOT_must_be_zero_or_one'),
                ('snapshot-requires-readonly',0,1,1,'STAGE90_DWC3_CLOCK_SNAPSHOT_requires_READONLY_and_TARGET_READS'),
                ('snapshot-requires-target',1,0,1,'STAGE90_DWC3_CLOCK_SNAPSHOT_requires_READONLY_and_TARGET_READS')):
            build(label, source, enabled=enabled, target=target, irq=1,
                  snapshot=snapshot, compile_error=marker)
            print('PASS invalid mode:',label,'rejected by explicit compile-time contract')
    for path, before in zip(files,snapshots):
        if path.read_bytes() != before: raise ValueError('source changed during test: '+str(path))
        print('SHA256',hashlib.sha256(before).hexdigest(),path.name)
    print('LIMIT: fake CPU, time, logs and guarded loads; no ARM/abort/bus/hardware proof')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit('FAIL: '+str(error))
