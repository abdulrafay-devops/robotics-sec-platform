#!/usr/bin/env python3
"""
Stage 3 - Safety Supervisor (the real safety brain / "Guard A").

This is the controller that actually guards the cell on Modbus port 503. It
runs the rung-for-rung Python translation of ``vm-ot/openplc/safety_supervisor.st``:

  1. **Modbus TCP server on port 503** - receives the production PLC's
     heartbeat (written by ``safety_heartbeat.py`` at 5 Hz). Holding registers:
       HR[0]  hb_counter   (UINT, monotonic, wraps at 2**16)
       HR[1]  prod_state   (UINT: 0=idle, 1=run, 2=fault)
       HR[2]  remote_estop (UINT: 0 normal, non-zero = E-stop, 9 = admin reset)
       HR[10] safety_state (mirror out: 0=NORMAL, 1=DEGRADED, 2=EMERGENCY)
       HR[11] ack_counter  (mirror out: echoes accepted hb_counter)
       HR[12] last_fault   (mirror out: reason for the last EMERGENCY)

  2. **Safety state machine** - heartbeat watchdog (500 ms), replay/regression
     guard, production-fault trip, and remote E-stop. Transitions to EMERGENCY
     are **LATCHED**: only an explicit, deliberate reset (HR[2] == 9) returns
     the system to NORMAL.

RUN MODES
---------
* ``--modbus-only`` (used in the container): runs ONLY the Modbus safety server
  and the safety state machine. It does NOT create a ROS2 node. In the lab the
  SROS2 publishing of /safety/state and the subscription to /safety/request -
  plus mirroring safety state onto the production PLC - are handled by the
  companion ``safety_bridge.py`` process, which owns the single
  ``safety_supervisor`` SROS2 node. Keeping this process ROS-free avoids a
  duplicate-node clash while still putting the real watchdog/latch/replay logic
  on duty at :503.

* default (standalone): also brings up the SROS2 node itself (publisher of
  /safety/state, subscriber of /safety/request) for running this supervisor on
  its own without the bridge. ROS2 is imported lazily so ``--modbus-only`` has
  no ROS dependency at all.

Note on authorization: DDS-Security (SROS2) enforces certificate-based
*authentication* of every participant. Topic-level *authorization* (ACLs) is a
separate control; see ``bootstrap_keystore.sh`` for its current status.
"""
from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

# ---------- Modbus server (heartbeat receiver) --------------------------
from pymodbus.datastore import (  # noqa: E402
    ModbusSequentialDataBlock,
    ModbusSlaveContext,
    ModbusServerContext,
)
from pymodbus.server import StartTcpServer  # noqa: E402

LOG = logging.getLogger("safety_supervisor")

# Safety state constants - must match safety_supervisor.st.
NORMAL = 0
DEGRADED = 1
EMERGENCY = 2

# Fault codes - must match safety_supervisor.st.
FAULT_NONE = 0
FAULT_HEARTBEAT = 1
FAULT_PROD_FAULT = 2
FAULT_REMOTE_ESTOP = 3
FAULT_REPLAY = 4


@dataclass
class SafetyState:
    """Mutable state shared between the Modbus server thread and the ROS2 node."""

    safety_state: int = NORMAL
    ack_counter: int = 0
    last_hb_counter: int = 0
    last_hb_wall_time: float = field(default_factory=time.monotonic)
    last_fault_code: int = FAULT_NONE
    remote_estop_requested: bool = False
    estop_request_time: float = 0.0  # wall-clock when E-stop arrived
    estop_latched_time: float = 0.0  # wall-clock when state flipped to EMERGENCY
    # The watchdog is ARMED only after the first heartbeat is observed.
    # This avoids a startup race where the production PLC is still
    # establishing its TCP session when the supervisor's 500 ms timer
    # would otherwise fire FAULT_HEARTBEAT.
    first_hb_received: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)

    def latch_emergency(self, fault: int) -> None:
        """Latched transition into EMERGENCY. Cannot un-latch except by reset."""
        with self.lock:
            if self.safety_state != EMERGENCY:
                self.safety_state = EMERGENCY
                self.last_fault_code = fault
                self.estop_latched_time = time.monotonic()
                LOG.warning(
                    "EMERGENCY latched, fault=%d (HEARTBEAT=1, PROD=2, REMOTE=3, REPLAY=4)",
                    fault,
                )


# ---------- Modbus server callbacks -------------------------------------
class _HeartbeatReceiver:
    """Periodically polls our own Modbus context to detect production heartbeats.

    pymodbus has no per-register "on-write" hook in the synchronous TCP server
    API we use here, so we poll the holding registers from a background
    thread. 50 ms scan time matches the ST `SafetyTask` interval.
    """

    # 10 ms scan: fast enough to reliably catch the momentary HR[2] E-stop(1)/
    # reset(9) pulses from the HMI before the 5 Hz heartbeat rewrites HR[2]=0
    # (matches the responsiveness of the prior :503 server, so no regression).
    # The .st reference task is 50 ms; scanning faster is strictly safer.
    SCAN_INTERVAL_S = 0.01
    # Heartbeat watchdog window. The heartbeat runs at 5 Hz (200 ms), so 2.0 s is
    # ~10 beats of tolerance: a momentary TCP blip / reconnect no longer starves
    # the watchdog into a false EMERGENCY, while a genuine heartbeat loss (process
    # truly dead for >2 s) still trips. (Was 0.5 s, which latched on a sub-second
    # blip - see the OT heartbeat-reconnect incident.)
    HB_TIMEOUT_S = 2.0

    def __init__(self, context: ModbusServerContext, state: SafetyState) -> None:
        self._context = context
        self._state = state
        self._stop = threading.Event()

    def run(self) -> None:
        LOG.info("heartbeat receiver loop started (50ms scan)")
        while not self._stop.is_set():
            try:
                self._scan_once()
            except Exception as exc:  # noqa: BLE001
                LOG.error("scan failed: %s", exc, exc_info=True)
            self._stop.wait(self.SCAN_INTERVAL_S)

    def stop(self) -> None:
        self._stop.set()

    def _scan_once(self) -> None:
        # Slave id 0 (broadcast) holds our registers. pymodbus stores
        # registers in 0-indexed sequential blocks under address 0.
        slave = self._context[0]
        # getValues(register_type, addr, count). register_type 3 = HR.
        hr = slave.getValues(3, 0, 6)
        hb_counter, prod_state, remote_estop_reg = int(hr[0]), int(hr[1]), int(hr[2])
        slow_req = int(hr[5])  # HR[5]: optional slow-mode/DEGRADED request (parity with prior server)
        now = time.monotonic()

        with self._state.lock:
            # Admin reset (HR[2] == 9): the ONLY way out of a latched state.
            if remote_estop_reg == 9:
                self._state.safety_state = NORMAL
                self._state.last_fault_code = FAULT_NONE
                self._state.remote_estop_requested = False
                self._state.first_hb_received = False
                # Clear the remote_estop register on the slave context
                slave.setValues(3, 2, [0])
                # Mirror out the cleared state immediately and finish this scan.
                slave.setValues(3, 10, [self._state.safety_state])
                slave.setValues(3, 12, [self._state.last_fault_code])
                return

            # Heartbeat sequence handling.
            if hb_counter == self._state.last_hb_counter:
                pass  # no new beat this scan; staleness is handled by the watchdog below
            elif hb_counter > self._state.last_hb_counter:
                # Normal fresh increment -> reset watchdog timestamp + ack.
                self._state.last_hb_counter = hb_counter
                self._state.last_hb_wall_time = now
                self._state.ack_counter = hb_counter
                self._state.first_hb_received = True
                slave.setValues(3, 11, [hb_counter & 0xFFFF])  # reflect ack into HR[11]
            elif (self._state.last_hb_counter - hb_counter) >= 1000:
                # Large backward jump => the heartbeat SOURCE restarted (counter
                # reset to a low value) or the 16-bit counter wrapped. Treat it as
                # a fresh re-baseline, NOT a replay attack, so a heartbeat restart
                # or reconnect does not starve the watchdog into a false E-stop.
                LOG.warning("heartbeat counter reset/wrap (%d -> %d); re-baselining",
                            self._state.last_hb_counter, hb_counter)
                self._state.last_hb_counter = hb_counter
                self._state.last_hb_wall_time = now
                self._state.ack_counter = hb_counter
                self._state.first_hb_received = True
                slave.setValues(3, 11, [hb_counter & 0xFFFF])
            else:
                # Small backward step => genuine replay/regression (FAULT_REPLAY).
                self._unsafe_latch(FAULT_REPLAY, now)
                slave.setValues(3, 10, [self._state.safety_state])
                slave.setValues(3, 12, [self._state.last_fault_code])
                return

            # Heartbeat watchdog (FAULT_HEARTBEAT). Only armed after the
            # production PLC delivers its first heartbeat (see SafetyState
            # docstring for why startup gets a grace period).
            if self._state.first_hb_received and (
                now - self._state.last_hb_wall_time
            ) >= self.HB_TIMEOUT_S:
                if self._state.safety_state != EMERGENCY:
                    self._unsafe_latch(FAULT_HEARTBEAT, now)

            # Production self-reported fault (FAULT_PROD_FAULT).
            if prod_state == 2:
                self._unsafe_latch(FAULT_PROD_FAULT, now)

            # Remote E-stop (FAULT_REMOTE_ESTOP): set via Modbus HR[2] != 0
            # (e.g. the HMI/score_service writes 1) OR by the bridge on an
            # authenticated /safety/request.
            if remote_estop_reg != 0 or self._state.remote_estop_requested:
                self._unsafe_latch(FAULT_REMOTE_ESTOP, now)

            # Non-latching DEGRADED request (slow mode) when not in EMERGENCY.
            # Preserves the prior server's HR[5]==1 behaviour; harmless if unused.
            if (self._state.safety_state == NORMAL) and slow_req == 1:
                self._state.safety_state = DEGRADED
                self._state.last_fault_code = FAULT_NONE
            elif (self._state.safety_state == DEGRADED) and slow_req != 1:
                self._state.safety_state = NORMAL

            # Mirror state/fault out so external Modbus pollers (the bridge) can read.
            slave.setValues(3, 10, [self._state.safety_state])
            slave.setValues(3, 12, [self._state.last_fault_code])

    def _unsafe_latch(self, fault: int, now: float) -> None:
        """Caller MUST hold state.lock."""
        if self._state.safety_state != EMERGENCY:
            self._state.safety_state = EMERGENCY
            self._state.last_fault_code = fault
            self._state.estop_latched_time = now
            LOG.warning("EMERGENCY latched (fault=%d)", fault)


# ---------- main --------------------------------------------------------
def _start_modbus_thread(host: str, port: int, context: ModbusServerContext) -> threading.Thread:
    t = threading.Thread(
        target=StartTcpServer,
        kwargs={"context": context, "address": (host, port)},
        name="modbus-server",
        daemon=True,
    )
    t.start()
    return t


def _run_ros_node(state: SafetyState) -> int:
    """Standalone mode only: bring up the SROS2 node for /safety/state and
    /safety/request. ROS2 is imported lazily so --modbus-only needs no ROS deps."""
    import rclpy  # noqa: E402
    from rclpy.node import Node  # noqa: E402
    from rclpy.qos import (  # noqa: E402
        QoSDurabilityPolicy,
        QoSHistoryPolicy,
        QoSProfile,
        QoSReliabilityPolicy,
    )
    from std_msgs.msg import UInt8  # noqa: E402

    class _SafetyNode(Node):
        """Publishes /safety/state, subscribes to /safety/request."""

        PUBLISH_PERIOD_S = 0.05

        def __init__(self, st: SafetyState) -> None:
            super().__init__("safety_supervisor")
            self._state = st
            state_qos = QoSProfile(
                history=QoSHistoryPolicy.KEEP_LAST,
                depth=10,
                reliability=QoSReliabilityPolicy.RELIABLE,
                durability=QoSDurabilityPolicy.TRANSIENT_LOCAL,
            )
            self._state_pub = self.create_publisher(UInt8, "/safety/state", state_qos)
            self._req_sub = self.create_subscription(
                UInt8, "/safety/request", self._on_request, 10
            )
            self.create_timer(self.PUBLISH_PERIOD_S, self._publish_state)
            self.get_logger().info("safety_supervisor ROS2 node up")

        def _publish_state(self) -> None:
            msg = UInt8()
            with self._state.lock:
                msg.data = int(self._state.safety_state)
            self._state_pub.publish(msg)

        def _on_request(self, msg: UInt8) -> None:
            if msg.data != 0:
                now = time.monotonic()
                with self._state.lock:
                    self._state.remote_estop_requested = True
                    self._state.estop_request_time = now
                self.get_logger().warning("authenticated remote E-stop received")

    rclpy.init(args=sys.argv)
    node = _SafetyNode(state)

    def _shutdown(*_a) -> None:
        LOG.info("shutdown requested")
        if rclpy.ok():
            rclpy.shutdown()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    rc = 0
    try:
        rclpy.spin(node)
    except Exception as exc:  # noqa: BLE001
        LOG.error("safety_supervisor crashed: %s", exc, exc_info=True)
        rc = 1
    finally:
        node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()
    return rc


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    p.add_argument("--bind-host", default=os.environ.get("LAB_SAFETY_HOST", "0.0.0.0"))
    p.add_argument("--bind-port", type=int, default=int(os.environ.get("LAB_SAFETY_PORT", "503")))
    p.add_argument("--modbus-only", action="store_true",
                   help="Run only the Modbus safety server + state machine (no ROS2 node). "
                        "Used in the container; safety_bridge.py owns the SROS2 node.")
    p.add_argument("--log-level", default=os.environ.get("LAB_LOG_LEVEL", "INFO"))
    args = p.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    # Initial Modbus context: 16 holding registers, zeroed.
    block = ModbusSequentialDataBlock(0, [0] * 16)
    slave = ModbusSlaveContext(hr=block, zero_mode=True)
    context = ModbusServerContext(slaves=slave, single=True)

    state = SafetyState()
    receiver = _HeartbeatReceiver(context, state)
    recv_thread = threading.Thread(target=receiver.run, name="hb-receiver", daemon=True)
    recv_thread.start()

    if args.modbus_only:
        # Proven pattern (identical to the prior :503 server): run the Modbus TCP
        # server in the MAIN thread; the safety state machine runs in the receiver
        # thread started above. No ROS2 here - safety_bridge.py owns the node.
        LOG.info("MODBUS-ONLY mode: safety brain active (watchdog+latch+replay) on "
                 "%s:%d; SROS2 handled by safety_bridge.py", args.bind_host, args.bind_port)
        try:
            StartTcpServer(context=context, address=(args.bind_host, args.bind_port))
        except (KeyboardInterrupt, SystemExit):
            pass
        finally:
            receiver.stop()
            LOG.info("safety_supervisor (modbus-only) exiting")
        return 0

    # Standalone mode: Modbus server in a background thread + SROS2 node in main.
    modbus_thread = _start_modbus_thread(args.bind_host, args.bind_port, context)
    LOG.info("Modbus safety server listening on %s:%d", args.bind_host, args.bind_port)
    rc = _run_ros_node(state)
    receiver.stop()
    LOG.info("safety_supervisor exiting (rc=%d, modbus_thread_alive=%s)",
             rc, modbus_thread.is_alive())
    return rc


if __name__ == "__main__":
    sys.exit(main())
