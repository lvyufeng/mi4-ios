#ifndef SPMI_S2_READ_H
#define SPMI_S2_READ_H
#include <stdbool.h>
#include <stdint.h>
/* Original code, numeric oracles only: spmi-pmic-arb.c:34,40-46,69-102,
 * 149-152,180-196,277-327; qpnp-regulator.c:99-150,294-297,637-659;
 * msm8974.dtsi:848-859; msm-pm8841.dtsi:70-114. No copied vendor bodies.
 * Caller establishes actual DT v1/channel0/EE0/SID5, S2 0x1700 type 1c08,
 * exclusive channel use. Raw version is not an authorization/version gate.
 * Normal barrier-write/status protocol accepts old DONE; no independent
 * new completion epoch proof. No APID/owner/config/IRQ/reset/SCM writes.
 * write32=0 means guarded store completed with barriers and state checks;
 * any nonzero (including 8) is indeterminate, NEVER retried. read32/time_us
 * =0 success; ignore failed output poison. ctx may be NULL. Callbacks log
 * actual guard evidence. Reliable monotonic us required; admission deadline
 * cannot bound a stuck MMIO/callback. delay_us performs bounded 1us wait.
 * Inputs/out must not alias. No direct MMIO/production caller/PMIC write.
 */
enum spmi_s2_result {
    SPMI_S2_OK, SPMI_S2_INVALID, SPMI_S2_READ_FAILED, SPMI_S2_WRITE_FAILED,
    SPMI_S2_TIME_FAILED, SPMI_S2_TIME_LIMIT, SPMI_S2_BAD_STATUS,
    SPMI_S2_DENIED, SPMI_S2_TIMEOUT, SPMI_S2_BAD_RANGE,
    SPMI_S2_BAD_ENCODING, SPMI_S2_NOT_RUN, SPMI_S2_DELAY_FAILED
};
enum spmi_s2_stage {
    SPMI_S2_VALIDATE, SPMI_S2_VERSION, SPMI_S2_PRESTATUS,
    SPMI_S2_DIAGNOSTIC, SPMI_S2_COMMAND, SPMI_S2_POLL,
    SPMI_S2_DATA, SPMI_S2_DECODE, SPMI_S2_DONE
};
enum spmi_s2_event_kind { SPMI_S2_READ, SPMI_S2_WRITE, SPMI_S2_TIME, SPMI_S2_DELAY };
struct spmi_s2_callbacks {
    int (*read32)(void *, uint32_t, uint32_t *);
    int (*write32)(void *, uint32_t, uint32_t);
    int (*time_us)(void *, uint64_t *);
    int (*delay_us)(void *, uint32_t);
};
/* 207 reads + 2 writes + 198 delays, each clock gated, start+final =816. */
#define SPMI_S2_MAX_EVENTS 816u
struct spmi_s2_event {
    enum spmi_s2_event_kind kind;
    enum spmi_s2_stage stage;
    uint32_t transaction, address;
    uint64_t value;
    int result;
};
/* valid_mask: bit0 version, bit1 first data, bit2 second data; transaction
 * is zero-based. stage_status includes later decode/final-clock failures.
 * setpoint_uv is programmed FTSMPS setpoint, NOT electrical ADC/supply floor.
 * Mode/enable flags are requests, not actual mode/ready; >=900mV is advisory.
 * clock_write_authorized/supply_floor_proven/adc_measurement always false. */
struct spmi_s2_output {
    enum spmi_s2_result result, stage_status[2];
    enum spmi_s2_stage stage;
    uint32_t current_transaction, failed_address, valid_mask;
    uint32_t version, pre_status[2], diagnostic_before[2];
    uint32_t completion_status[2], polls[2], data_raw[2];
    bool pre_status_valid[2], diagnostic_valid[2], completion_valid[2], sample_valid[2];
    uint32_t read_attempts, read_completed, write_attempted, write_completed;
    uint32_t time_attempts, time_completed, delay_attempts, delay_completed;
    bool time_valid, indeterminate, decoded;
    uint64_t start_us, last_us;
    uint8_t range_raw, vset_raw, mode_raw, enable_raw;
    uint32_t setpoint_uv;
    bool hpm_requested, auto_requested, enabled_request, nominal_reference_met;
    bool setpoint_conversion, clock_write_authorized, supply_floor_proven, adc_measurement;
    uint32_t event_count;
    struct spmi_s2_event events[SPMI_S2_MAX_EVENTS];
};
extern const uint32_t spmi_s2_read_commands[2];
extern const uint32_t spmi_s2_read_registers[4];
enum spmi_s2_result spmi_s2_read(const struct spmi_s2_callbacks *, void *, struct spmi_s2_output *);
#endif
