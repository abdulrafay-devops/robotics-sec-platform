(* SIGNED_BY: lab-release@lab.local @ 2026-06-06T12:00:00Z *)
(* Demo jog routine for the lab robot arm (hardened version - passes all gates). *)

PROGRAM JOG_CONTROL
  VAR_INPUT
    jog_request   : BOOL;
    e_stop_active : BOOL;
    safety_ok     : BOOL;
  END_VAR
  VAR_OUTPUT
    jog_allowed : BOOL;
  END_VAR
  VAR
    i : UINT;
  END_VAR

  (* Motion is permitted only when the E-stop is clear AND the safety supervisor agrees. *)
  IF jog_request AND NOT e_stop_active AND SAFETY_OK THEN
      jog_allowed := TRUE;
      FOR i := 0 TO 50 DO                    (* bounded by a static literal *)
          jog_allowed := TRUE;
      END_FOR;
  ELSE
      jog_allowed := FALSE;
  END_IF;

END_PROGRAM

PROGRAM SAFETY_JOG_OUTPUT
  VAR_INPUT
    jog_allowed   : BOOL;
    e_stop_active : BOOL;
  END_VAR
  (* Safety-owned block: ONLY here may the %QX0.x safety output be driven. *)
  IF jog_allowed AND NOT e_stop_active AND SAFETY_OK THEN
      %QX0.0 := TRUE;
  ELSE
      %QX0.0 := FALSE;
  END_IF;
END_PROGRAM
