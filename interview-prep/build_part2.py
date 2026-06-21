# -*- coding: utf-8 -*-
"""Part 2 — The Plant Floor (OT & Safety)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _pdfkit import (P, H1, H2, H3, small, spacer, bullets, code, callout, tbl,
                     rule, keep, build, CONTENT_W, PageBreak)

st = []

# ============================================================ COVER
st += [
    P('Robotics Security Platform', 'title'),
    P('Interview Preparation &mdash; Part 2 of 4: The Plant Floor (OT &amp; Safety)', 'subtitle'),
    rule(),
    P('This part goes down into the most important and most dangerous zone: the OT plant floor. We cover the PLC and the code it runs, the robot it drives, the Modbus language they speak (and how it is attacked), the SROS2 certificate security on the robot\'s messaging, and &mdash; the centrepiece &mdash; the independent safety system that guarantees the robot fails safe. By the end you can explain exactly how a stopped robot stays stopped until a human says otherwise.', 'body'),
    callout('The single most important sentence in this whole part: <b>"Safety is independent of security, and clearing a safe state is always a deliberate human action."</b> Everything below is evidence for that sentence.', 'why'),
]

# ============================================================ PLC
st += [PageBreak(), H1('1.  The PLC and its program')]
st += [
    H2('1.1  What the PLC is doing'),
    P('The production PLC runs <b>OpenPLC</b>, and its program is the file <b>vm-ot/openplc/production.st</b>, written in <b>Structured Text</b> (an industrial programming language, standard IEC 61131-3). The program is a <b>6-step pick-and-place cycle</b> that repeats on a fixed <b>100&nbsp;ms scan</b> &mdash; meaning the whole program re-runs ten times a second, forever.', 'body'),
    code(
"""  step 0: idle      -> wait for a start button
  step 1: convey    -> run conveyor, enable arm        (1.0 s)
  step 2: move      -> arm moves to the pick position  (1.5 s)
  step 3: grip      -> close the gripper               (0.5 s)
  step 4: move      -> arm moves to the place position (1.5 s)
  step 5: release   -> open the gripper                (0.5 s)
  step 6: complete  -> count one finished cycle, loop back to step 1"""),
    P('It exposes its state on Modbus registers so the rest of the system can watch it: <b>%MW0</b> = current step, <b>%MW1</b> = completed-cycle count, <b>%MW2</b> = how many times the E-stop has tripped.', 'body'),
    H2('1.2  The safety-first interlock (the most important lines of PLC code)'),
    P('Right at the top of the program, before any motion logic, is the safety interlock. In plain words it says: <b>"If the emergency stop is active OR a safe-state has been requested, immediately drop every output (motor, gripper, conveyor) and hold at step 0."</b>', 'body'),
    code(
"""safe_state_now := e_stop_active OR request_safe_state ;

IF safe_state_now THEN
    motor_arm_enable := FALSE ;   -- kill the arm
    gripper_close    := FALSE ;   -- release
    conveyor_run     := FALSE ;   -- stop the belt
    cycle_step       := 0    ;    -- freeze at the start
    (count one E-stop trip the first scan it goes active)
END_IF ;"""),
    callout('Because this check runs first on every 100&nbsp;ms scan, there is no situation where the machine keeps moving once a safe-state is asserted. That is what "fail safe" looks like in actual code &mdash; not a comment, an interlock at the top of the loop.', 'why'),
    P('There is also a <b>slow mode</b>: a flag (%MW4) that, when set, roughly doubles every step\'s duration &mdash; the software equivalent of slowing the line to a reduced safe speed instead of fully stopping it. The incident-response engine uses this (Part 3).', 'body'),
]

# ============================================================ ROBOT
st += [PageBreak(), H1('2.  The robot (the simulated arm)')]
st += [
    P('The physical arm is simulated in <b>Gazebo</b> (a 3D robotics simulator) and driven by a ROS2 program, <b>vm-ot/gazebo/cyclic_motion.py</b>. It is a 6-jointed arm (joints j1&ndash;j6) that follows a fixed, recorded trajectory between five waypoints:', 'body'),
    bullets([
        'A = home pose &rarr; B = above the pick zone &rarr; C = at the pick zone &rarr; D = above the drop zone &rarr; E = at the drop zone.',
        'Motion is smoothed with cosine interpolation, so the movement looks natural &mdash; and so the ML models see coherent, learnable dynamics.',
    ]),
    P('Crucially, the motion node <b>subscribes to the safety state</b> (the <b>/safety/state</b> topic). When the safety system says EMERGENCY, the robot stops commanding new positions and <b>freezes at its last waypoint</b>. So the robot itself obeys the safety system, not just the PLC.', 'body'),
    callout('Why simulate the robot? Because you <b>never test attacks on a real production line</b> &mdash; a false move can injure someone or cost a fortune in downtime. The Gazebo arm is a "digital twin": a realistic copy you can safely attack and experiment on. Real plants do exactly this. (You will use this point again when defending the design in Part 4.)', 'ex'),
]

# ============================================================ MODBUS + ATTACKS
st += [PageBreak(), H1('3.  Modbus, and how it gets attacked')]
st += [
    H2('3.1  How Modbus works (in one minute)'),
    P('Modbus/TCP is how the PLC is read and commanded over the network. It has two kinds of data: <b>coils</b> (single on/off bits, like "conveyor on/off") and <b>registers</b> (16-bit numbers, like "current step = 3"). Every operation is a numbered <b>function code</b> &mdash; for example FC&nbsp;3 reads registers, FC&nbsp;6 writes one register, FC&nbsp;16 writes many. <b>Reads are FC 1&ndash;4; writes are FC 5, 6, 15, 16, 22, 23.</b>', 'body'),
    callout('Modbus has <b>no authentication, no encryption, no integrity check</b>. Whoever can reach the port can command the PLC. This is not a bug we introduced &mdash; it is the reality of most industrial protocols, and it is precisely <i>why</i> the rest of this platform (segmentation, monitoring, the independent safety system) has to exist.', 'why'),
    H2('3.2  The four traffic generators'),
    P('To have something to detect, the project ships one "normal" generator and three attack simulators (in <b>vm-ot/traffic/</b>). The normal one teaches the ML models what good looks like; the attacks deviate from it on purpose.', 'body'),
    tbl([
        ['Script', 'What it does', 'What is supposed to catch it'],
        ['modbus_normal.py', 'Acts as an authorised HMI: reads a fixed set of registers at a steady 5&nbsp;Hz. This is the baseline of "normal".', 'Nothing &mdash; it is the good traffic the models learn from.'],
        ['attack_modbus_inject.py', 'Command injection: writes to coils the baseline never writes (motor enable, conveyor) and forces odd step values.', 'Suricata rule, the ML models (write from a non-HMI source IP), and the safety supervisor independently.'],
        ['attack_modbus_flood.py', 'Flood: a high-rate burst of writes &mdash; the volume itself is the attack.', 'The ML models (message-rate and write-ratio features spike).'],
        ['attack_modbus_replay.py', 'Replay: re-sends previously captured legitimate-looking frames to fake activity.', 'The ML models and the safety supervisor\'s replay/regression guard.'],
    ], [0.26 * CONTENT_W, 0.42 * CONTENT_W, 0.32 * CONTENT_W]),
    callout('"The classic cyber-physical attack is a Modbus write-burst from outside the OT zone &mdash; a register that is normally only read suddenly gets written, from an IP that is not the HMI. My feature pipeline is built around exactly that signal (see the n_external_writes feature in Part 3)."', 'say'),
]

# ============================================================ SROS2
st += [PageBreak(), H1('4.  SROS2 &mdash; securing the robot\'s messaging')]
st += [
    P('The robot\'s own messages (joint commands, and the all-important safety topics) travel over ROS2/DDS. By default DDS is open &mdash; any program on the network can publish or subscribe. <b>SROS2</b> closes that with a certificate system (a small <b>PKI</b>, public-key infrastructure).', 'body'),
    H2('4.1  The keystore and enclaves'),
    P('A bootstrap script (<b>bootstrap_keystore.sh</b>) creates a certificate authority and four "enclaves" &mdash; each enclave is an identity with its own certificate:', 'body'),
    tbl([
        ['Enclave (identity)', 'Role'],
        ['/lab/safety_supervisor', 'Owns the safety topics: publishes /safety/state, subscribes to /safety/request.'],
        ['/lab/production_plc', 'The heartbeat publisher; allowed to publish E-stop requests on /safety/request.'],
        ['/lab/ai_subscriber', 'Read-only: may subscribe to /safety/state (the analytics tier just watches).'],
        ['/lab/cyclic_motion', 'The robot motion node; subscribes to /safety/state so it can freeze.'],
    ], [0.36 * CONTENT_W, 0.64 * CONTENT_W]),
    P('There is also a deliberately <b>absent</b> identity, /lab/test_unauthorized, used by a test to prove that a program <i>without</i> a valid certificate is rejected and cannot speak the protocol at all.', 'body'),
    H2('4.2  The honest, important nuance: authentication vs authorization'),
    P('This is a favourite interview probe, so be precise:', 'body'),
    bullets([
        '<b>Authentication IS enforced.</b> Every participant must present a certificate signed by the lab\'s authority. An attacker with no certificate cannot join the robot\'s DDS conversation &mdash; full stop.',
        '<b>Topic-level authorization (ACLs) is NOT enforced</b> in the running system. The intended rules (e.g. "ai_subscriber must never publish to /safety/request") exist as XML files but are not active.',
    ]),
    callout('Be honest about why: when the authors signed and installed the per-topic permission files, <b>Cyclone DDS silently hung during discovery</b> &mdash; the whole robot messaging layer failed to start. They reverted to the default (authenticate, but do not enforce per-topic ACLs) to keep the system working, and documented the ACL files as intended future work. "Authentication is enforced cryptographically; topic ACLs are the documented next step once the DDS discovery issue is resolved." Saying this scores maturity points.', 'warn'),
]

# ============================================================ SAFETY SYSTEM
st += [PageBreak(), H1('5.  The safety system (the heart of the OT story)')]
st += [
    P('This is the part to know cold. The safety function is split across <b>three small programs</b> so that the guardian is independent of the thing it guards.', 'body'),
    H2('5.1  The three players'),
    tbl([
        ['Program', 'Where it runs', 'Its one job'],
        ['safety_heartbeat.py', 'Production side', 'Every 0.2&nbsp;s (5&nbsp;Hz) write a "I am alive" counter to the safety controller over Modbus.'],
        ['safety_supervisor.py', 'The safety controller on port 503', 'The real "safety brain": watchdog, latch, and replay guard. Decides NORMAL / DEGRADED / EMERGENCY.'],
        ['safety_bridge.py', 'The single SROS2 node', 'Translate between the secure robot topics and Modbus, and mirror the safety state onto the production PLC and the robot.'],
    ], [0.27 * CONTENT_W, 0.24 * CONTENT_W, 0.49 * CONTENT_W]),
    callout('A bit of project history worth knowing: a simpler stand-in used to guard port 503 (no watchdog, no latch) while the documentation described the smart supervisor. That gap was closed &mdash; <b>safety_supervisor.py now actually runs the port-503 server in "--modbus-only" mode</b>, so the real watchdog/latch/replay logic is genuinely on duty. If asked about "claimed vs actual", this is the honest answer: it was a gap, and it was fixed.', 'note', label='A GOOD STORY TO TELL'),
    H2('5.2  The register contract (how they talk over Modbus port 503)'),
    code(
"""Production heartbeat WRITES:               Supervisor MIRRORS OUT (read-only):
  HR[0]  hb_counter   (counts up, wraps)      HR[10] safety_state  0=NORMAL
  HR[1]  prod_state   (1 = running)                              1=DEGRADED
  HR[2]  remote_estop  0 = normal                                2=EMERGENCY
                       1 = E-stop request     HR[11] ack_counter (echoes hb)
                       9 = admin RESET        HR[12] last_fault  (why it tripped)"""),
    H2('5.3  The four ways the supervisor trips EMERGENCY'),
    bullets([
        '<b>Heartbeat lost (watchdog).</b> If no fresh heartbeat arrives for ~2 seconds, the production side is presumed dead or cut off &mdash; trip EMERGENCY. (The watchdog only arms after the first heartbeat, so startup is not a false trip.)',
        '<b>Production reports a fault.</b> If the production side sets prod_state = fault, trip.',
        '<b>Remote E-stop.</b> If an E-stop request arrives (HR[2]=1 via Modbus, or an authenticated request over SROS2), trip.',
        '<b>Replay / regression.</b> If the heartbeat counter steps <i>backwards</i> a little, that smells like replayed old traffic &mdash; trip with FAULT_REPLAY. (A <i>big</i> backwards jump is treated as an honest restart or 16-bit wrap, not an attack, so a reconnect does not cause a false alarm.)',
    ]),
    H2('5.4  Latched &mdash; and only a human clears it'),
    P('Once EMERGENCY is set, it is <b>latched</b>: the supervisor will not return to NORMAL on its own, even if the heartbeat comes back. The <b>only</b> way out is a deliberate reset &mdash; writing the value <b>9</b> to register HR[2]. That mirrors real functional-safety practice: a machine must never silently restart itself after a safety event; a person must look, decide, and reset.', 'body'),
    callout('"EMERGENCY is latched. Loss of heartbeat trips it within about two seconds, and it stays tripped until a deliberate reset &mdash; the robot cannot un-stop itself." Then add the honest caveat below.', 'say'),
    callout('Honest caveat: the reset (register = 9) exists as a Modbus write. In the IDMZ, the analytics zone and IT have <b>no firewall path to the safety port</b> &mdash; any legitimate control rides the authenticated OT control gateway, not a raw write &mdash; so it is not network-reachable from outside OT. The remaining gap is that the safety controller is still a <b>software simulator co-located in OT</b>. <b>For a real cell, the top change is an independent hardware SIS (IEC 61511) whose reset is a local, physical, deliberate action with no network path at all.</b>', 'warn'),
]

# ============================================================ FULL LOOP
st += [PageBreak(), H1('6.  The complete safety &amp; control loop')]
st += [
    P('Putting it together &mdash; this is the picture to draw on a whiteboard:', 'body'),
    code(
"""  PRODUCTION SIDE                         SAFETY SIDE (independent)
  +------------------+    5 Hz heartbeat   +---------------------------+
  | safety_heartbeat |--- HR[0] counter -->| safety_supervisor (:503)  |
  | (writes :503)    |                     |  - watchdog (~2 s)        |
  +------------------+                     |  - replay/regression guard|
                                           |  - LATCHED EMERGENCY      |
  OPERATOR clicks E-stop on dashboard      +-------------+-------------+
        |  /api/hmi/control (key)                        | HR[10] state
        v                                                v
  score_service -- HR[2]=1 --> :503 ........ supervisor latches EMERGENCY
                                                         |
                            +----------------------------+
                            v  safety_bridge mirrors state
        +-------------------+--------------------+
        |                                        |
   production PLC :502                     robot over SROS2
   (e_stop_active := TRUE,                 (/safety/state = EMERGENCY)
    drops all outputs)                     robot freezes at last waypoint
        |
   RECOVERY: operator writes HR[2]=9  -> NORMAL  -> cell resumes (deliberate)"""),
    spacer(4),
    H2('Likely questions (with crisp answers)'),
    tbl([
        ['Question', 'Answer'],
        ['What if the network drops?', 'The heartbeat stops, the watchdog trips EMERGENCY within ~2 seconds, and the robot freezes. The loop is local, so a WAN/internet outage never affects it.'],
        ['Could an attacker un-latch the E-stop?', 'In the lab the reset is over Modbus (demo convenience), but the ports are bound to localhost. In production I would remove every network path to the reset and make it physical-only.'],
        ['Is the safety system really independent?', 'It runs as its own process on its own port with its own watchdog and latch, separate from the production controller. In a real plant I would make it a physically separate Safety Instrumented System (IEC 61511).'],
        ['Authentication or authorization on ROS2?', 'Authentication is enforced (every node needs a CA-signed certificate). Topic-level ACLs are at the permissive default because enforcing them hung Cyclone DDS; that is documented future work.'],
    ], [0.34 * CONTENT_W, 0.66 * CONTENT_W]),
    spacer(4),
    rule(),
    P('<b>End of Part 2.</b> You can now explain the plant floor: the PLC cycle and its safety interlock, the simulated robot, the Modbus protocol and its attacks, SROS2 certificate security, and the independent, latched safety system. <b>Part 3</b> goes up into the brain: how traffic becomes features, how three ML models score it, how incidents are handled, and how the code itself is secured by the CI/CD pipeline.', 'body'),
]

build(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'Part2-Plant-Floor-OT-and-Safety.pdf'),
      'Part 2: The Plant Floor (OT &amp; Safety)', st)
print('Part 2 OK')
