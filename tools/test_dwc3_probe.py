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
static struct stage90_guarded_read32_state fault_evidence;
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
    0xfc4003c0u,0xfc4003d4u,0xf920c120u,0xf920c110u,0xf920c140u,
    0xf920c144u,0xf920c200u,0xf920c700u,0xf920c704u,0xf920c70cu
};
static uint32_t values[15] = {1u,1u,1u,1u,1u,0u,2u,0x5533220au,
    0x12340008u,0x12340009u,0x1234000au,0x1234000bu,0x1234000cu,0x1234000du,0x1234000eu};
static uint32_t seen[20];
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
        "dwc3_ro_guard_cpsr_before","dwc3_ro_guard_cpsr_after"};
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
        for(j=1u;j<20u;++j) CHECK(address!=golden[j]);
        CHECK(effects.logs>0u && !strcmp(logs[effects.logs-1u].key,"dwc3_ro_guard_ram_address"));
        CHECK(logs[effects.logs-1u].value==address && *out==0xa55a12edu);
        golden[0]=address;
        stage90_guarded_read32_state.cpsr_before_mask=0x13u;
        stage90_guarded_read32_state.cpsr_after_mask=0xd3u;
        if(guard_case>=16) {
            static const uint32_t missing[]={0x40u,0x80u,0xc0u};
            stage90_guarded_read32_state.cpsr_after_mask &= ~missing[guard_case-16];
            stage90_guarded_read32_state.status=STAGE90_GUARDED_BAD_CONTEXT;
            return STAGE90_GUARDED_BAD_CONTEXT;
        }
        if(guard_case==1) return -7;
        *out=guard_case==2 ? 0x47524451u : 0x47524450u;
        stage90_guarded_read32_state.status=STAGE90_GUARDED_OK;
        return 0;
    }
    CHECK(address==golden[i]);
    if(i==1u) {
        struct stage90_guarded_read32_state state={0};
        CHECK(*out==0xa55a12edu);
        state.expected_address=address; state.status=STAGE90_GUARDED_FAULT; state.fault_count=1u;
        state.fault_dfar=address; state.fault_dfsr=5u;
        state.fault_pc=state.observed_pc=(uint32_t)(uintptr_t)stage90_guarded_read32_fault;
        state.recovery_pc=(uint32_t)(uintptr_t)stage90_guarded_read32_recovery;
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
static void callback_checks(void)
{
    struct dwc3_probe_context ctx={0u,0u};
    uint32_t value=0x12345678u;
    static const uint32_t bad[]={0u,0xf9017008u,0xf901700cu,0xfc400109u,0xf920c124u,0xffffffffu};
    unsigned i;
    direct=1;
    for(i=0;i<sizeof(bad)/sizeof(bad[0]);++i) CHECK(dwc3_probe_read(&ctx,bad[i],&value)!=0);
    CHECK(dwc3_probe_read(NULL,golden[5],&value)!=0);
    CHECK(dwc3_probe_read(&ctx,golden[5],NULL)!=0);
    ctx.attempted=15u; CHECK(dwc3_probe_read(&ctx,golden[5],&value)!=0);
    ctx.attempted=0u; now=10001u; CHECK(dwc3_probe_read(&ctx,golden[5],&value)!=0);
    CHECK(effects.reads==0u && effects.logs==0u && ctx.attempted==0u && value==0x12345678u);
    ctx.attempted=14u; now=10000u; value=0u;
    CHECK(dwc3_probe_read(&ctx,golden[5],&value)==0);
    CHECK(ctx.attempted==15u && value==1u && effects.reads==1u);
    CHECK(dwc3_probe_read(&ctx,golden[5],&value)!=0 && effects.reads==1u);
    ctx.attempted=0u; fail=1; value=0xabcdef01u;
    CHECK(dwc3_probe_read(&ctx,golden[5],&value)==-7 && value==0xabcdef01u);
    CHECK(ctx.attempted==1u && effects.reads==2u);
}
int main(int argc, char **argv)
{
    const char *name;
    unsigned p, expected=20u, completed=15u, slot=UINT32_MAX, status=MI4_DWC3_IDENTIFY_OK;
    unsigned clocks=31u, regs=255u, summary=1u, delays=1u, i, read_logs=0u, value_logs=0u;
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
    if(!strcmp(name,"cpu")) {
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
        CHECK(p<18u); fail=(int)p+2; expected=p+3u;
        if(p<3u) { summary=0u; delays=p==2u; } else {
            slot=p-3u; completed=slot; status=MI4_DWC3_IDENTIFY_READ_FAILED;
            clocks=(1u<<(slot<5u ? slot : 5u))-1u; regs=slot>7u ? (1u<<(slot-7u))-1u : 0u;
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
        if(!(value&1u) || ((value>>28)!=0u && (value>>28)!=2u)) {
            completed=index+1u;expected=completed+5u;clocks=(1u<<completed)-1u;regs=0u;
            status=MI4_DWC3_IDENTIFY_CLOCK_BLOCKED;
        }
    } else if(!strcmp(name,"reset")) {
        values[5]=1u;completed=6u;expected=11u;regs=0u;status=MI4_DWC3_IDENTIFY_RESET_ASSERTED;
    } else if(!strcmp(name,"root")) {
        static const uint32_t bad[]={0u,1u,3u,0x80000002u,0x12u,0x22u,0x42u,0x82u};
        CHECK(p<8u);values[6]=bad[p];completed=7u;expected=12u;regs=0u;status=MI4_DWC3_IDENTIFY_ROOT_BLOCKED;
    } else if(!strcmp(name,"id")) {
        values[7]=0x55320000u;completed=8u;expected=13u;regs=1u;status=MI4_DWC3_IDENTIFY_WRONG_ID;
    } else if(!strcmp(name,"deadline")) {
        step=10001u;expected=5u;completed=clocks=regs=0u;slot=0u;status=MI4_DWC3_IDENTIFY_READ_FAILED;
    } else CHECK(!strcmp(name,"golden"));
    if(skip && guard_case<0) { expected=summary=delays=0u; }
    stage90_dwc3_readonly_probe();
    CHECK(effects.reads==expected && effects.delays==delays);
    for(i=0;i<expected;++i) CHECK(seen[i]==golden[i]);
    CHECK(strstr(text,"DWC3 read-only identity probe;")!=NULL);
    if(skip) CHECK(strstr(text,skip)!=NULL);
    CHECK((strstr(text,"dwc3_ro finished;")!=NULL)==summary);
    CHECK((strstr(text,"guard selftest passed:")!=NULL)==(expected>=3u));
    if(expected>0u) kv("dwc3_ro_guard_ram_address",golden[0]);
    if(expected>1u) {
        kv("dwc3_ro_guard_fault_address",0xdeadc000u);
        kv("dwc3_ro_guard_fault_result",guard_case==3 ? 0u : guard_case==15 ? (uint32_t)-7 : STAGE90_GUARDED_FAULT);
        kv("dwc3_ro_guard_fault_dfsr",fault_evidence.fault_dfsr);
        kv("dwc3_ro_guard_fault_dfar",fault_evidence.fault_dfar);
        kv("dwc3_ro_guard_fault_pc",fault_evidence.observed_pc);
    }
    for(i=0;i<effects.logs;++i) {
        if(!strcmp(logs[i].key,"dwc3_ro_read_index")) CHECK(logs[i].value==++read_logs);
        if(!strcmp(logs[i].key,"dwc3_ro_read_address")) {
            CHECK(read_logs>0u && read_logs<=15u && logs[i].value==golden[read_logs+4u]);
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
    names = ['dwc3_probe.c', 'dwc3_identify.c', 'dwc3_identify.h', 'stage90.h', 'stage90_guarded_read32.h']
    files = [root/'src'/name for name in names]; snapshots = [p.read_bytes() for p in files]
    source = cpu_fixture(snapshots[0].decode())
    cases = [('golden', 0), ('callback', 0), ('en-off', 0), ('reset', 0), ('id', 0), ('deadline', 0)]
    for name, count in [('cpu',14), ('precondition',8), ('mapping',4), ('watchdog',7),
                        ('fault',18), ('selftest',19), ('counter',7), ('clock',5), ('clock-state',32), ('root',8)]:
        cases.extend((name, i) for i in range(count))
    with tempfile.TemporaryDirectory(prefix='mi4-dwc3-probe-') as tmp:
        directory = Path(tmp)
        for name, content in [('stage90.h', stage90_stub(snapshots[3].decode())),
                              ('stage90_guarded_read32.h', snapshots[4].decode()), ('harness.c', HARNESS),
                              ('dwc3_identify.c', snapshots[1].decode()), ('dwc3_identify.h', snapshots[2].decode())]:
            (directory/name).write_text(content)
        def build(label, probe, enabled):
            (directory/'actual-probe.c').write_text(probe)
            binary = directory/label
            flags = ['-std=c11', '-O0', '-Wall', '-Wextra', '-Werror', '-pedantic',
                     '-DSTAGE90_DWC3_READONLY='+str(enabled), '-I', str(directory)]
            if args.sanitize: flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
            result = command(cc+flags+[str(directory/'harness.c'), str(directory/'dwc3_identify.c'), '-o', str(binary)])
            if result.returncode: raise ValueError(label+' compile failed:\n'+result.stderr)
            return binary
        def run(binary, case):
            result = command([str(binary), case[0], str(case[1])])
            if result.returncode: raise ValueError(str(case)+' failed:\n'+result.stdout+result.stderr)
            match = re.fullmatch(r'PASS (\d+)\n', result.stdout)
            if not match: raise ValueError('unexpected harness output: '+result.stdout)
            return int(match[1])
        actual = build('actual-on', source, 1)
        checks = sum(run(actual, case) for case in cases)
        # OFF compiles the original, entirely untouched source (no CPU seam needed).
        checks += run(build('actual-off', snapshots[0].decode(), 0), ('off', 0))
        print('PASS:', len(cases)+1, 'fresh-process ON/OFF cases,', checks, 'C assertions')
        gate = ('if (!watchdog || !watchdog->enabled || !watchdog->counter_running ||\n'
                '        !watchdog->countdown_plausible || !watchdog->readback_ok ||\n'
                '        watchdog->bite_truncated || !stage90_deadman_armed())')
        controls = [('watchdog-gate', gate, 'if (!watchdog)', ('watchdog',1)),
                    ('address-whitelist', '!dwc3_probe_address_allowed(address)',
                     '(0 && !dwc3_probe_address_allowed(address))', ('callback',0)),
                    ('one-shot', 'if (attempted) return;', 'if (attempted > 1u) return;', ('golden',0)),
                    ('guard-selftest', 'if (!dwc3_probe_guard_selftest(table)) return;',
                     '(void)dwc3_probe_guard_selftest(table);', ('selftest',5))]
        for label, old, new, case in controls:
            binary = build(label, replace_once(source,old,new), 1)
            result = command([str(binary),case[0],str(case[1])])
            if result.returncode == 0 or 'CHECK line ' not in result.stderr:
                raise ValueError('negative must fail a C assertion, not compile/crash: '+label+'\n'+result.stderr)
            print('PASS negative:',label,'rejected by actual C behavior')
    for path, before in zip(files,snapshots):
        if path.read_bytes() != before: raise ValueError('source changed during test: '+str(path))
        print('SHA256',hashlib.sha256(before).hexdigest(),path.name)
    print('LIMIT: fake CPU, time, logs and guarded loads; no ARM/abort/bus/hardware proof')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit('FAIL: '+str(error))
