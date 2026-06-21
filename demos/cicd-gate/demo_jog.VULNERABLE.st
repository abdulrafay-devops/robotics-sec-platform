(* Demo jog routine for the lab robot arm. *)
(* WARNING: intentionally insecure - used to prove the DevSecOps PLC gate fails the build. *)

PROGRAM JOG_CONTROL
  VAR_INPUT
    jog_request  : BOOL;
    target_steps : UINT;
    operator_pin : STRING := 'admin';     (* R1: hard-coded credential *)
  END_VAR
  VAR
    i : UINT;
  END_VAR

  (* R2: motion block with NO e-stop / safety guard at all *)
  IF jog_request THEN
      %QX0.0 := TRUE;                       (* R3: safety output written outside a SAFETY_ block *)
      FOR i := 0 TO target_steps DO         (* R4: unbounded FOR loop (bound is a variable) *)
          %QX0.2 := TRUE;
      END_FOR;
  END_IF;

  (* SAFETY_INTERLOCK_CHECK(jog_request) *)  (* R5: safety check commented out / disabled *)

END_PROGRAM
