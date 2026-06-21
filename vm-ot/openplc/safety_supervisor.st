(* SIGNED_BY: lab-release@lab.local @ 2026-05-19T22:00:00Z *)
(*
 * Safety Supervisor — IEC 61131-3 Structured Text reference ladder.
 *
 * This file is the *normative specification* of the safety logic. The
 * lab actually executes the same logic in Python (see
 * vm-ot/sros2/safety_supervisor.py) so we can co-locate the SROS2
 * (DDS) authentication layer in one process. The Python implementation
 * mirrors this ST file rung-for-rung; any change here MUST be reflected
 * there. Use this file as the artifact you would deploy to a real
 * second OpenPLC (192.168.10.11:503) when porting to hardware.
 *
 * Inputs  (Modbus holding registers received from production PLC):
 *   %MW0  hb_counter      : monotonic heartbeat (1 Hz baseline, 5 Hz under load)
 *   %MW1  prod_state      : production PLC operating state (0=idle, 1=run, 2=fault)
 *   %MW2  remote_estop    : 1 if a (cryptographically authenticated) remote E-stop was issued
 *
 * Outputs (Modbus holding registers polled by the runtime to publish /safety/state):
 *   %MW10 safety_state    : 0=NORMAL, 1=DEGRADED, 2=EMERGENCY
 *   %MW11 ack_counter     : echoes hb_counter when last accepted
 *   %MW12 last_fault_code : reason for the most recent EMERGENCY transition
 *
 * Fault codes (last_fault_code):
 *   0  no fault
 *   1  heartbeat watchdog (no hb_counter increment within HB_TIMEOUT)
 *   2  production reported its own fault (prod_state == 2)
 *   3  authenticated remote E-stop request
 *   4  invalid hb_counter sequence (replay/regression)
 *)

PROGRAM SafetySupervisor

  VAR_INPUT
    hb_counter   : UINT;
    prod_state   : UINT;
    remote_estop : BOOL;
  END_VAR

  VAR_OUTPUT
    safety_state    : UINT := 0;     (* NORMAL *)
    ack_counter     : UINT := 0;
    last_fault_code : UINT := 0;
  END_VAR

  VAR
    last_hb         : UINT := 0;
    hb_watchdog     : TON;
    hb_changed      : BOOL := FALSE;
  END_VAR

  (* --- 1. Detect a fresh heartbeat (counter incremented since last scan). *)
  hb_changed := (hb_counter <> last_hb) AND (hb_counter > last_hb);

  (* --- 2. Replay/regression guard: counter must monotonically increase. *)
  IF (hb_counter < last_hb) AND (last_hb - hb_counter < 1000) THEN
      safety_state    := 2;          (* EMERGENCY *)
      last_fault_code := 4;
  END_IF;

  (* --- 3. Heartbeat watchdog. Reset on each fresh hb. *)
  hb_watchdog(IN := NOT hb_changed, PT := T#500ms);

  IF hb_watchdog.Q AND (safety_state <> 2) THEN
      safety_state    := 2;
      last_fault_code := 1;
  END_IF;

  (* --- 4. Production self-reported fault. *)
  IF prod_state = 2 THEN
      safety_state    := 2;
      last_fault_code := 2;
  END_IF;

  (* --- 5. Authenticated remote E-stop. *)
  IF remote_estop THEN
      safety_state    := 2;
      last_fault_code := 3;
  END_IF;

  (* --- 6. Once EMERGENCY is latched it must remain latched until the
   *       supervisor process is restarted. There is no "auto-clear"
   *       transition from EMERGENCY back to NORMAL inside this scan. *)

  (* --- 7. Health bookkeeping for diagnostics. *)
  IF hb_changed THEN
      ack_counter := hb_counter;
      last_hb     := hb_counter;
  END_IF;

END_PROGRAM


CONFIGURATION Config0

  RESOURCE Res0 ON PLC
    TASK SafetyTask(INTERVAL := T#50ms, PRIORITY := 0);
    PROGRAM SafetyInst WITH SafetyTask : SafetySupervisor;
  END_RESOURCE

END_CONFIGURATION
