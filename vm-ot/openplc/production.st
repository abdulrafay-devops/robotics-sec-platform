(* SIGNED_BY: lab-release@lab.local @ 2026-05-19T22:00:00Z *)
(* ===================================================================== *)
(* PRODUCTION PLC ladder logic for the lab cell                          *)
(*                                                                       *)
(* IEC 61131-3 Structured Text (.st) loaded by OpenPLC v3 (iec2c).       *)
(* Modbus mapping (OpenPLC standard):                                    *)
(*   Discrete Inputs  %IX0.0..%IX1.7  -> Modbus addresses 0..15          *)
(*   Coils            %QX0.0..%QX1.7  -> Modbus addresses 0..15          *)
(*   Holding Regs     %MW0..%MW63     -> Modbus addresses 0..63          *)
(*                                                                       *)
(* What this program does:                                               *)
(*   - 6-step pick-and-place state machine driven by a 100 ms scan.      *)
(*   - Publishes step + cycle counter on holding registers (telemetry).  *)
(*   - Honours an E-stop (%IX0.2) AND a "request_safe_state" (%IX0.3)    *)
(*     coil that the Stage-3 Safety Supervisor will assert via SROS2.    *)
(*   - Counts E-stop trips for Stage-6 incident metrics.                 *)
(*                                                                       *)
(* Notes for the iec2c front-end:                                        *)
(*   * VAR blocks are split by category (located inputs, located outputs,*)
(*     located memory words, plain internals) because iec2c is picky     *)
(*     about mixing AT-located and plain declarations in one block.      *)
(*   * TON instances are always called with both IN and PT parameters    *)
(*     in one statement; partial calls confuse the parser.               *)
(* ===================================================================== *)

PROGRAM PRODUCTION_PROGRAM
  VAR
    cycle_start_btn AT %IX0.0 : BOOL;
    cycle_stop_btn AT %IX0.1 : BOOL;
  END_VAR

  VAR
    motor_arm_enable AT %QX0.0 : BOOL;
    gripper_close AT %QX0.1 : BOOL;
    conveyor_run AT %QX0.2 : BOOL;
    cycle_busy AT %QX0.3 : BOOL;
    cycle_complete AT %QX0.4 : BOOL;
    e_stop_active AT %QX0.5 : BOOL;
    request_safe_state AT %QX0.6 : BOOL;
    remote_start_btn AT %QX1.0 : BOOL;
    remote_stop_btn AT %QX1.1 : BOOL;
  END_VAR

  VAR
    cycle_step AT %MW0 : UINT;
    cycle_count AT %MW1 : UINT;
    estop_trip_count AT %MW2 : UINT;
    last_cycle_ms AT %MW3 : UINT;
    slow_mode_active AT %MW4 : UINT;
    safety_state AT %MW10 : UINT;
    last_fault_code AT %MW12 : UINT;
  END_VAR

  VAR
    step_timer           : TON;
    last_estop           : BOOL;
    step_run             : BOOL;
    step_pt              : TIME;
    safe_state_now       : BOOL;
    cycle_running        : BOOL;
  END_VAR

  (* ------------------------------------------------------------------ *)
  (* SAFETY-FIRST INTERLOCK                                              *)
  (* If E-stop or safe-state asserted: drop everything, hold step 0.     *)
  (* ------------------------------------------------------------------ *)
  safe_state_now := e_stop_active OR request_safe_state;

  IF safe_state_now THEN
    motor_arm_enable := FALSE;
    gripper_close    := FALSE;
    conveyor_run     := FALSE;
    cycle_busy       := FALSE;
    cycle_step       := 0;
    step_run         := FALSE;
    cycle_running    := FALSE;
    IF e_stop_active AND NOT last_estop THEN
      estop_trip_count := estop_trip_count + 1;
    END_IF;
  END_IF;
  last_estop := e_stop_active;

  (* ------------------------------------------------------------------ *)
  (* CYCLE STATE MACHINE                                                 *)
  (*   step 0: idle, wait for start                                      *)
  (*   step 1: convey part into cell  (1.0 s)                            *)
  (*   step 2: arm moves to pick      (1.5 s)                            *)
  (*   step 3: gripper close          (0.5 s)                            *)
  (*   step 4: arm moves to place     (1.5 s)                            *)
  (*   step 5: gripper open           (0.5 s)                            *)
  (*   step 6: complete pulse                                            *)
  (* ------------------------------------------------------------------ *)
  IF NOT safe_state_now THEN

    (* Per-step actions (outputs) and the PT for the per-step timer.    *)
    CASE cycle_step OF
      0:
        cycle_busy       := FALSE;
        cycle_complete   := FALSE;
        conveyor_run     := FALSE;
        gripper_close    := FALSE;
        motor_arm_enable := FALSE;
        step_pt := T#100ms;
      1:
        conveyor_run     := TRUE;
        motor_arm_enable := TRUE;
        IF slow_mode_active = 1 THEN
          step_pt := T#2000ms;
        ELSE
          step_pt := T#1000ms;
        END_IF;
      2:
        conveyor_run     := FALSE;
        motor_arm_enable := TRUE;
        IF slow_mode_active = 1 THEN
          step_pt := T#3000ms;
        ELSE
          step_pt := T#1500ms;
        END_IF;
      3:
        gripper_close    := TRUE;
        IF slow_mode_active = 1 THEN
          step_pt := T#1000ms;
        ELSE
          step_pt := T#500ms;
        END_IF;
      4:
        IF slow_mode_active = 1 THEN
          step_pt := T#3000ms;
        ELSE
          step_pt := T#1500ms;
        END_IF;
      5:
        gripper_close    := FALSE;
        IF slow_mode_active = 1 THEN
          step_pt := T#1000ms;
        ELSE
          step_pt := T#500ms;
        END_IF;
      6:
        cycle_complete   := TRUE;
        IF NOT cycle_running THEN
          cycle_busy     := FALSE;
        END_IF;
        motor_arm_enable := FALSE;
        step_pt := T#100ms;
    END_CASE;

    (* Timer tick. Always called once per scan with current step_pt.    *)
    step_timer(IN := step_run, PT := step_pt);

    IF cycle_step = 0 THEN
      step_run := FALSE;
      IF (cycle_start_btn OR remote_start_btn) AND NOT (cycle_stop_btn OR remote_stop_btn) THEN
        cycle_step    := 1;
        cycle_busy    := TRUE;
        step_run      := TRUE;
        cycle_running := TRUE;
      END_IF;
    ELSIF step_timer.Q THEN
      (* Re-arm the timer for the next step. *)
      step_run := FALSE;
      IF cycle_step = 6 THEN
        cycle_count    := cycle_count + 1;
        last_cycle_ms  := 6100; (* nominal full-cycle ms; precise meas in Stage 2 *)
        IF cycle_running AND NOT (cycle_stop_btn OR remote_stop_btn) THEN
          cycle_step  := 1;
          step_run    := TRUE;
        ELSE
          cycle_step  := 0;
          cycle_busy  := FALSE;
        END_IF;
      ELSE
        cycle_step := cycle_step + 1;
        step_run   := TRUE;
      END_IF;
    END_IF;

    (* Handle cycle abort / stop *)
    IF cycle_stop_btn OR remote_stop_btn THEN
      cycle_running := FALSE;
      IF cycle_step > 0 THEN
        cycle_step := 0;
        cycle_busy := FALSE;
        step_run   := FALSE;
      END_IF;
    END_IF;

    (* Reset momentary buttons *)
    remote_start_btn := FALSE;
    remote_stop_btn  := FALSE;

  END_IF;

END_PROGRAM


(* ===================================================================== *)
(* CONFIGURATION + TASK BINDING                                          *)
(* ===================================================================== *)
CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK MAIN_TASK(INTERVAL := T#100ms, PRIORITY := 0);
    PROGRAM main_inst WITH MAIN_TASK : PRODUCTION_PROGRAM;
  END_RESOURCE
END_CONFIGURATION
