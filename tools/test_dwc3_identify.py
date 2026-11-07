#!/usr/bin/env python3
"""Compile the actual read-only DWC3 inspection core; no hardware adapter.

All generated files live under a new temporary directory. Supplier headers and
sources are read-only numerical oracles, not imported or executed. This does not
prove a powered peripheral is safe to access, USB connectivity, or bounded MMIO.
"""
import argparse
import hashlib
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

HARNESS = r'''
#include "dwc3_identify.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks, cases;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"case=%u line=%d: %s\n",cases,__LINE__,#x); exit(1); } } while (0)
static const uint32_t addresses[] = {
    0xfc400108u,0xfc4003c8u,0xfc4003d0u,0xfc4003ccu,0xfc4004acu,
    0xfc4003c0u,0xfc4003d4u,0xf920c120u,0xf920c110u,0xf920c140u,
    0xf920c144u,0xf920c200u,0xf920c700u,0xf920c704u,0xf920c70cu
};
struct mock { uint32_t values[15]; unsigned calls, fail; };
static int read32(void *context, uint32_t address, uint32_t *value)
{
    struct mock *m = context;
    unsigned index = m->calls++;
    CHECK(index < 15u);
    CHECK(address == addresses[index]);
    if (index == m->fail) { *value = 0xdeadbeefu; return -1; }
    *value = m->values[index];
    return 0;
}
static struct mock fresh(void)
{
    struct mock m = {{1u,1u,1u,1u,1u,0u,2u,0x5533210au,
                      0x2000u,0x12345678u,0x87654321u,0x40u,0u,0x80000000u,0u},0u,99u};
    ++cases;
    return m;
}
static void invoke(struct mock *m, struct mi4_dwc3_identity *out,
                   enum mi4_dwc3_identify_status expected, unsigned reads)
{
    uint32_t before[15];
    memcpy(before,m->values,sizeof(before));
    memset(out,0xa5,sizeof(*out));
    CHECK(mi4_dwc3_identify(read32,m,out) == expected);
    CHECK(out->status == expected && m->calls == reads);
    CHECK(memcmp(before,m->values,sizeof(before)) == 0);
}
static int snapshot_read32(void *context, uint32_t address, uint32_t *value)
{
    struct mock *m = context;
    CHECK(m->calls < 7u);
    return read32(context,address,value);
}
static void invoke_snapshot(struct mock *m, struct mi4_dwc3_identity *out)
{
    uint32_t before[15];
    unsigned i, completed=m->fail<7u ? m->fail : 7u;
    enum mi4_dwc3_identify_status status=m->fail<7u ?
        MI4_DWC3_IDENTIFY_READ_FAILED : MI4_DWC3_IDENTIFY_OK;
    memcpy(before,m->values,sizeof(before));
    memset(out,0xa5,sizeof(*out));
    CHECK(mi4_dwc3_clock_snapshot(snapshot_read32,m,out)==status);
    CHECK(out->status==status && m->calls==completed+(m->fail<7u));
    CHECK(out->completed_reads==completed);
    CHECK(out->failed_slot==(m->fail<7u ? m->fail : UINT32_MAX));
    CHECK(out->valid_clocks==((1u<<(completed<5u ? completed : 5u))-1u));
    CHECK(out->bcr_valid==(completed>5u) && out->root_valid==(completed>6u));
    CHECK(out->bcr==(completed>5u ? m->values[5] : 0u));
    CHECK(out->root_command==(completed>6u ? m->values[6] : 0u));
    CHECK(out->valid_registers==0u);
    for(i=0;i<5u;++i) CHECK(out->clock_values[i]==(i<completed ? m->values[i] : 0u));
    for(i=0;i<8u;++i) CHECK(out->registers[i]==0u);
    CHECK(memcmp(before,m->values,sizeof(before))==0);
}
static void snapshot_cases(void)
{
    struct mi4_dwc3_identity out;
    struct mock m;
    unsigned i,j,enabled;
    checks=cases=0;
    CHECK(mi4_dwc3_clock_snapshot(NULL,NULL,NULL)==MI4_DWC3_IDENTIFY_INVALID);
    m=fresh();
    CHECK(mi4_dwc3_clock_snapshot(snapshot_read32,&m,NULL)==MI4_DWC3_IDENTIFY_INVALID);
    CHECK(m.calls==0u);
    memset(&out,0xa5,sizeof(out));
    CHECK(mi4_dwc3_clock_snapshot(NULL,NULL,&out)==MI4_DWC3_IDENTIFY_INVALID);
    CHECK(out.status==MI4_DWC3_IDENTIFY_INVALID && out.completed_reads==0u);
    CHECK(out.valid_clocks==0u && out.valid_registers==0u && out.failed_slot==UINT32_MAX);
    CHECK(out.bcr_valid==0u && out.root_valid==0u && out.bcr==0u && out.root_command==0u);
    for(i=0;i<5u;++i) CHECK(out.clock_values[i]==0u);
    for(i=0;i<8u;++i) CHECK(out.registers[i]==0u);
    /* Runtime first-branch HALT, asserted reset and blocked root are data only. */
    m=fresh();m.values[0]=0x80000000u;m.values[5]=1u;m.values[6]=0x800000f3u;
    invoke_snapshot(&m,&out);
    for(i=0;i<5u;++i) for(j=0;j<16u;++j) for(enabled=0;enabled<2u;++enabled) {
        m=fresh();m.values[i]=((uint32_t)j<<28)|enabled;
        invoke_snapshot(&m,&out);
    }
    m=fresh();for(i=0;i<7u;++i)m.values[i]=0xffffffffu;
    invoke_snapshot(&m,&out);
    for(i=0;i<7u;++i) {
        m=fresh();m.fail=i;
        invoke_snapshot(&m,&out); /* Failed callback poisons its local output. */
    }
    printf("PASS snapshot: %u cases, %u assertions; seven GCC reads only, not identification\n",cases,checks);
}
static const uint32_t root_addresses[13] = {
    0xfc400108u,0xfc4003c8u,0xfc4003d0u,0xfc4003ccu,0xfc4004acu,
    0xfc4003c0u,0xfc4003d4u,0xfc4003d8u,0xfc4003dcu,0xfc4003e0u,
    0xfc4003e4u,0xfc40001cu,0xfc401480u
};
static int root_read32(void *context, uint32_t address, uint32_t *value)
{
    struct mock *m=context;
    unsigned slot=m->calls++;
    CHECK(slot<13u && address==root_addresses[slot]);
    if(slot==m->fail) { *value=0xdeadbeefu;return -1; }
    *value=m->values[slot];return 0;
}
static void invoke_root(struct mock *m, struct mi4_dwc3_root_snapshot *out)
{
    uint32_t before[15];
    unsigned i, completed=m->fail<13u ? m->fail : 13u;
    enum mi4_dwc3_identify_status expected=m->fail<13u ?
        MI4_DWC3_IDENTIFY_READ_FAILED : MI4_DWC3_IDENTIFY_OK;
    memcpy(before,m->values,sizeof(before));memset(out,0xa5,sizeof(*out));
    CHECK(mi4_dwc3_root_snapshot(root_read32,m,out)==expected);
    CHECK(out->clocks.status==expected && m->calls==completed+(m->fail<13u));
    CHECK(out->clocks.completed_reads==completed);
    CHECK(out->clocks.failed_slot==(m->fail<13u ? m->fail : UINT32_MAX));
    CHECK(out->clocks.valid_clocks==((1u<<(completed<5u ? completed : 5u))-1u));
    CHECK(out->clocks.bcr_valid==(completed>5u) && out->clocks.root_valid==(completed>6u));
    CHECK(out->clocks.bcr==(completed>5u ? m->values[5] : 0u));
    CHECK(out->clocks.root_command==(completed>6u ? m->values[6] : 0u));
    CHECK(out->clocks.valid_registers==0u);
    CHECK(out->valid_extra==(completed>7u ? (1u<<(completed-7u))-1u : 0u));
    for(i=0;i<5u;++i) CHECK(out->clocks.clock_values[i]==(i<completed ? m->values[i] : 0u));
    for(i=0;i<8u;++i) CHECK(out->clocks.registers[i]==0u);
    for(i=0;i<6u;++i) CHECK(out->values[i]==(completed>i+7u ? m->values[i+7u] : 0u));
    CHECK(memcmp(before,m->values,sizeof(before))==0);
}
static void root_cases(void)
{
    struct mi4_dwc3_root_snapshot out;
    struct mock m;
    unsigned i,j;
    checks=cases=0;
    CHECK(mi4_dwc3_root_snapshot(NULL,NULL,NULL)==MI4_DWC3_IDENTIFY_INVALID);
    m=fresh();
    CHECK(mi4_dwc3_root_snapshot(root_read32,&m,NULL)==MI4_DWC3_IDENTIFY_INVALID && m.calls==0u);
    memset(&out,0xa5,sizeof(out));
    CHECK(mi4_dwc3_root_snapshot(NULL,NULL,&out)==MI4_DWC3_IDENTIFY_INVALID);
    CHECK(out.clocks.status==MI4_DWC3_IDENTIFY_INVALID && out.clocks.completed_reads==0u);
    CHECK(out.clocks.failed_slot==UINT32_MAX && out.clocks.valid_clocks==0u);
    CHECK(out.clocks.bcr==0u && out.clocks.root_command==0u);
    CHECK(out.clocks.bcr_valid==0u && out.clocks.root_valid==0u);
    CHECK(out.clocks.valid_registers==0u && out.valid_extra==0u);
    for(i=0;i<5u;++i) CHECK(out.clocks.clock_values[i]==0u);
    for(i=0;i<8u;++i) CHECK(out.clocks.registers[i]==0u);
    for(i=0;i<6u;++i) CHECK(out.values[i]==0u);
    m=fresh();m.values[0]=0x80000000u;m.values[1]=0x8000cff0u;m.values[6]=0u;
    invoke_root(&m,&out);
    for(i=0;i<13u;++i) {
        m=fresh();m.fail=i;invoke_root(&m,&out);
    }
    /* All bit patterns are raw data: no enable/lock/ownership acceptance. */
    for(i=0;i<13u;++i) for(j=0;j<3u;++j) {
        m=fresh();m.values[i]=j==0u ? 0u : j==1u ? 0xffffffffu : 0x80020001u;
        invoke_root(&m,&out);
    }
    printf("PASS root snapshot: %u cases, %u assertions; thirteen raw GCC reads, not identification\n",cases,checks);
}
int main(void)
{
    struct mi4_dwc3_identity out;
    struct mock m;
    unsigned i,j;
    static const uint32_t blocked_clocks[] = {0u,2u,0x80000000u,0x80000001u,0xffffffffu};
    static const uint32_t blocked_roots[] = {0u,1u,3u,0x80000002u,0x12u,0x22u,0x42u,0x82u};
    static const uint32_t wrong_ids[] = {0u,0xffffffffu,0x55320000u,0x00005533u,0x12345678u};
    CHECK(mi4_dwc3_identify(NULL,NULL,NULL) == MI4_DWC3_IDENTIFY_INVALID);
    memset(&out,0xa5,sizeof(out));
    CHECK(mi4_dwc3_identify(NULL,NULL,&out) == MI4_DWC3_IDENTIFY_INVALID);
    CHECK(out.completed_reads == 0u && out.valid_clocks == 0u && out.valid_registers == 0u);
    CHECK(out.failed_slot == UINT32_MAX);
    for (i=0;i<5u;++i) for (j=0;j<sizeof(blocked_clocks)/sizeof(blocked_clocks[0]);++j) {
        m=fresh(); m.values[i]=blocked_clocks[j];
        invoke(&m,&out,MI4_DWC3_IDENTIFY_CLOCK_BLOCKED,i+1u);
        CHECK(out.completed_reads==i+1u && out.valid_clocks==((1u<<(i+1u))-1u));
        CHECK(out.valid_registers==0u && out.bcr_valid==0u && out.root_valid==0u);
        CHECK(out.failed_slot==UINT32_MAX);
    }
    for (i=0;i<5u;++i) for (j=0;j<16u;++j) {
        unsigned enabled;
        for (enabled=0;enabled<2u;++enabled) {
            unsigned good=enabled && (j==0u || j==2u);
            m=fresh();m.values[i]=((uint32_t)j<<28)|enabled;
            invoke(&m,&out,good?MI4_DWC3_IDENTIFY_OK:MI4_DWC3_IDENTIFY_CLOCK_BLOCKED,good?15u:i+1u);
            CHECK(out.valid_registers==(good?255u:0u));
        }
    }
    m=fresh(); m.values[5]=1u;
    invoke(&m,&out,MI4_DWC3_IDENTIFY_RESET_ASSERTED,6u);
    CHECK(out.bcr_valid==1u && out.root_valid==0u && out.valid_registers==0u);
    for (j=0;j<sizeof(blocked_roots)/sizeof(blocked_roots[0]);++j) {
        m=fresh();m.values[6]=blocked_roots[j];
        invoke(&m,&out,MI4_DWC3_IDENTIFY_ROOT_BLOCKED,7u);
        CHECK(out.completed_reads==7u && out.root_valid==1u && out.valid_registers==0u);
    }
    for (j=0;j<sizeof(wrong_ids)/sizeof(wrong_ids[0]);++j) {
        m=fresh();m.values[7]=wrong_ids[j];
        invoke(&m,&out,MI4_DWC3_IDENTIFY_WRONG_ID,8u);
        CHECK(out.valid_registers==1u && out.registers[0]==wrong_ids[j]);
        for(i=1;i<8u;++i) CHECK(out.registers[i]==0u);
    }
    for(i=0;i<15u;++i) {
        unsigned k;
        m=fresh();m.fail=i;
        invoke(&m,&out,MI4_DWC3_IDENTIFY_READ_FAILED,i+1u);
        CHECK(out.completed_reads==i && out.failed_slot==i);
        if(i<5u) CHECK(out.valid_clocks==((1u<<i)-1u));
        if(i==5u) CHECK(out.bcr_valid==0u);
        if(i==6u) CHECK(out.root_valid==0u);
        if(i>=7u) {
            CHECK(out.valid_registers==((1u<<(i-7u))-1u));
            for(k=i-7u;k<8u;++k) CHECK(out.registers[k]==0u);
        } else CHECK(out.valid_registers==0u);
    }
    m=fresh();invoke(&m,&out,MI4_DWC3_IDENTIFY_OK,15u);
    CHECK(out.completed_reads==15u && out.valid_clocks==31u && out.valid_registers==255u);
    CHECK(out.bcr_valid==1u && out.root_valid==1u && out.failed_slot==UINT32_MAX);
    for(i=0;i<8u;++i) CHECK(out.registers[i]==m.values[i+7u]);
    /* Unrelated clock/root bits are retained, not interpreted as speed/PLL proof. */
    m=fresh();for(i=0;i<5u;++i)m.values[i]|=0x2000cff0u;m.values[6]|=0x04000000u;
    m.values[7]=MI4_DWC3_REVISION_220A;
    invoke(&m,&out,MI4_DWC3_IDENTIFY_OK,15u);
    for(i=0;i<5u;++i) CHECK(out.clock_values[i]==m.values[i]);
    CHECK(out.root_command==m.values[6] && out.registers[0]==0x5533220au);
    printf("PASS: %u cases, %u assertions; read-only inspection core only\n",cases,checks);
    snapshot_cases();
    root_cases();
    return 0;
}
'''


def clean(text):
    return re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S)


def literal(text, name):
    values = re.findall(r'^\s*#\s*define\s+'+re.escape(name)+r'\s+(0x[0-9a-fA-F]+|[0-9]+)\s*$', clean(text), re.M)
    if len(values) != 1:
        raise ValueError('missing/ambiguous supplier literal '+name)
    return int(values[0], 0)


def oracle(root):
    base=root/'external/android_kernel_xiaomi_cancro'
    core=(base/'drivers/usb/dwc3/core.h').read_text()
    clocks=(base/'arch/arm/mach-msm/clock-8974.c').read_text()
    local=clean((base/'arch/arm/mach-msm/clock-local2.c').read_text())
    expected={'DWC3_GSNPSID':0xc120,'DWC3_GCTL':0xc110,'DWC3_GHWPARAMS0':0xc140,
              'DWC3_GHWPARAMS1':0xc144,'DWC3_DCFG':0xc700,'DWC3_DCTL':0xc704,
              'DWC3_DSTS':0xc70c,'DWC3_GSNPSID_MASK':0xffff0000,
              'DWC3_REVISION_220A':0x5533220a}
    for name,value in expected.items():
        if literal(core,name)!=value: raise ValueError('supplier mismatch '+name)
    for name,value in {'SYS_NOC_USB3_AXI_CBCR':0x108,'USB30_MASTER_CBCR':0x3c8,
                       'USB30_MOCK_UTMI_CBCR':0x3d0,'USB30_SLEEP_CBCR':0x3cc,
                       'USB2A_PHY_SLEEP_CBCR':0x4ac,'USB_30_BCR':0x3c0,
                       'USB30_MASTER_CMD_RCGR':0x3d4}.items():
        if literal(clocks,name)!=value: raise ValueError('supplier mismatch '+name)
    for name,bit in {'CBCR_BRANCH_ENABLE_BIT':0,'CBCR_BRANCH_OFF_BIT':31,
                     'CMD_RCGR_ROOT_ENABLE_BIT':1,'CMD_RCGR_ROOT_STATUS_BIT':31,
                     'CMD_RCGR_CONFIG_UPDATE_BIT':0,'BCR_BLK_ARES_BIT':0}.items():
        if not re.search(r'^\s*#define\s+'+name+r'\s+BIT\('+str(bit)+r'\)\s*$',local,re.M):
            raise ValueError('supplier bit mismatch '+name)
    if not re.search(r'^#define\s+CMD_RCGR_CONFIG_DIRTY_MASK\s+BM\(7,\s*4\)',local,re.M):
        raise ValueError('supplier dirty-mask mismatch')
    if not re.search(r'^#define\s+DWC3_GUSB2PHYCFG\(n\)\s+\(0xc200\s*\+',core,re.M):
        raise ValueError('supplier PHY offset mismatch')
    for name,expression in {'BRANCH_CHECK_MASK':r'BM\(31,\s*28\)',
                            'BRANCH_ON_VAL':r'BVAL\(31,\s*28,\s*0x0\)',
                            'BRANCH_NOC_FSM_ON_VAL':r'BVAL\(31,\s*28,\s*0x2\)'}.items():
        if not re.search(r'^\s*#define\s+'+name+r'\s+'+expression+r'\s*$',local,re.M):
            raise ValueError('supplier branch-state mismatch '+name)
    return 27


def execute(cc, directory, header, source, label, sanitized=False):
    h=directory/'dwc3_identify.h'; c=directory/(label+'.c'); harness=directory/'harness.c'
    if not h.exists():h.write_bytes(header)
    c.write_text(source)
    if not harness.exists():harness.write_text(HARNESS)
    binary=directory/label
    command=cc+['-std=c11','-O0','-Wall','-Wextra','-Werror','-pedantic','-I',str(directory)]
    if sanitized:command+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
    result=subprocess.run(command+[str(c),str(harness),'-o',str(binary)],capture_output=True,text=True,timeout=30)
    if result.returncode:return False,'compile: '+result.stderr
    result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=10)
    return result.returncode==0,result.stdout+result.stderr


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--vendor-root',type=Path)
    parser.add_argument('--cc',default='cc')
    parser.add_argument('--sanitize',action='store_true')
    args=parser.parse_args();root=args.repo_root.resolve()
    files=[root/'src/dwc3_identify.h',root/'src/dwc3_identify.c']
    snapshots=[p.read_bytes() for p in files]
    print('Supplier numerical checks:',oracle((args.vendor_root or root).resolve()))
    source=snapshots[1].decode();cc=shlex.split(args.cc)
    if not cc:raise ValueError('empty compiler')
    with tempfile.TemporaryDirectory(prefix='mi4-dwc3-identify-') as temp:
        directory=Path(temp)
        ok,detail=execute(cc,directory,snapshots[0],source,'actual',args.sanitize)
        print(detail,end='')
        if not ok:raise ValueError('actual implementation failed')
        clock_gate = ('if ((value & UINT32_C(1)) == 0 ||\n'
                      '            ((value & UINT32_C(0xf0000000)) != 0 &&\n'
                      '             (value & UINT32_C(0xf0000000)) != UINT32_C(0x20000000)))')
        controls=[('clock-gate',clock_gate,'if (0)'),
                  ('old-bit31-only',clock_gate,'if ((value & UINT32_C(0x80000001)) != UINT32_C(1))'),
                  ('id-gate','if (i == 0 && (value & MI4_DWC3_ID_MASK) != MI4_DWC3_ID_MAGIC)','if (0)'),
                  ('root-gate','if ((value & UINT32_C(0x800000f3)) != UINT32_C(2))','if (0)'),
                  ('snapshot-first-disabled-stop','if (i < MI4_DWC3_CLOCK_COUNT) {',
                   'if (value == UINT32_C(0x80000000)) return finish(out, MI4_DWC3_IDENTIFY_CLOCK_BLOCKED);\n'
                   '        if (i < MI4_DWC3_CLOCK_COUNT) {'),
                  ('snapshot-core-address','UINT32_C(0xfc4003d4)\n};',
                   'UINT32_C(0xf920c120)\n};'),
                  ('root-snapshot-core-address','UINT32_C(0xfc401480)\n};',
                   'UINT32_C(0xf920c120)\n};'),
                  ('root-snapshot-short-read','slot < 13u;', 'slot < 12u;')]
        for label,old,new in controls:
            if source.count(old)!=1:raise ValueError('mutation anchor changed: '+label)
            passed,detail=execute(cc,directory,snapshots[0],source.replace(old,new,1),label)
            if passed:raise ValueError('broken variant passed: '+label)
            if detail.startswith('compile:'):raise ValueError('negative must fail behavior, not compile: '+label)
            print('PASS negative',label,'rejected by actual C behavior')
    for p,before in zip(files,snapshots):
        if p.read_bytes()!=before:raise ValueError('source changed during test')
        print('SHA256',hashlib.sha256(before).hexdigest(),p.name)


if __name__=='__main__':
    try:main()
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        raise SystemExit('FAIL: '+str(error))
