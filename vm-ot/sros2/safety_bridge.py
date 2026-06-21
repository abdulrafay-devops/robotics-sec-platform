#!/usr/bin/env python3
"""
Stage 3 — SROS2-to-Modbus translator node (Safety Bridge).

Acts as the cryptographic access control gateway (safety bridge) running
under SROS2 enclave '/lab/safety_supervisor' on VM-OT.

It:
  1. Subscribes to SROS2-secured `/safety/request` (std_msgs/UInt8).
     On an E-stop request, it writes holding register %MW2 (remote_estop=1)
     to the safety OpenPLC runtime on localhost:503.
  2. Periodically polls the safety OpenPLC runtime on localhost:503
     holding register %MW10 (safety_state) and %MW12 (last_fault_code).
  3. Publishes safety_state to the SROS2-secured `/safety/state` topic.
"""

import argparse
import logging
import os
import signal
import sys
import threading
import time
from typing import Optional

from pymodbus.client import ModbusTcpClient
import rclpy
from rclpy.node import Node
from rclpy.qos import (
    QoSDurabilityPolicy,
    QoSHistoryPolicy,
    QoSProfile,
    QoSReliabilityPolicy,
)
from std_msgs.msg import UInt8

LOG = logging.getLogger("safety_bridge")


class SafetyBridgeNode(Node):
    def __init__(self, plc_host: str, plc_port: int, poll_period: float = 0.05) -> None:
        super().__init__("safety_supervisor")  # Keep the same node name so enclaves match!
        self._plc_host = plc_host
        self._plc_port = plc_port
        self._poll_period = poll_period
        
        self._client: Optional[ModbusTcpClient] = None
        self._prod_client: Optional[ModbusTcpClient] = None
        self._prod_host = "127.0.0.1"
        self._prod_port = 502
        
        self._safety_lock = threading.Lock()   # guards self._client (safety PLC)
        self._prod_lock = threading.Lock()     # guards self._prod_client (production PLC)
        
        self._last_synchronized_state = None
        self._last_synchronized_fault = None
        
        # QoS profiles: reliable + transient_local for safety state
        state_qos = QoSProfile(
            history=QoSHistoryPolicy.KEEP_LAST,
            depth=10,
            reliability=QoSReliabilityPolicy.RELIABLE,
            durability=QoSDurabilityPolicy.TRANSIENT_LOCAL,
        )
        self._state_pub = self.create_publisher(UInt8, "/safety/state", state_qos)
        
        # Subscribe to /safety/request
        self._req_sub = self.create_subscription(
            UInt8, "/safety/request", self._on_request, 10
        )
        
        # Connection management in a background thread or connection pool
        self._connect_to_plc()
        
        # Asynchronous background thread for polling Modbus safety state to prevent blocking the rclpy executor thread
        self._stop_polling = threading.Event()
        self._poll_thread = threading.Thread(target=self._poll_loop, name="modbus-poller", daemon=True)
        self._poll_thread.start()
        self.get_logger().info(f"safety_bridge node up, connected to OpenPLC at {plc_host}:{plc_port}")

    def _connect_to_plc(self) -> bool:
        with self._safety_lock:
            if self._client is not None and self._client.is_socket_open():
                return True
            try:
                self._client = ModbusTcpClient(self._plc_host, port=self._plc_port, timeout=1.0)
                ok = self._client.connect()
                if ok:
                    self.get_logger().info(f"Connected to safety OpenPLC Modbus server")
                return ok
            except Exception as exc:
                self.get_logger().warning(f"Failed to connect to safety OpenPLC: {exc}")
                self._client = None
                return False

    def _connect_to_prod_plc(self) -> bool:
        with self._prod_lock:
            if self._prod_client is not None and self._prod_client.is_socket_open():
                return True
            try:
                self._prod_client = ModbusTcpClient(self._prod_host, port=self._prod_port, timeout=1.0)
                ok = self._prod_client.connect()
                if ok:
                    self.get_logger().info("Connected to production OpenPLC Modbus server")
                return ok
            except Exception as exc:
                self.get_logger().debug(f"Failed to connect to production OpenPLC: {exc}")
                self._prod_client = None
                return False

    def _on_request(self, msg: UInt8) -> None:
        if msg.data != 0:
            self.get_logger().warning("Authenticated remote E-stop request received! Writing to OpenPLC %MW2...")
            t = threading.Thread(target=self._write_estop_plc, args=(1,), daemon=True)
            t.start()

    def _write_estop_plc(self, value: int) -> None:
        for attempt in range(3):
            if self._connect_to_plc():
                try:
                    with self._safety_lock:
                        # Write remote_estop holding register at address 2
                        result = self._client.write_register(2, value)
                        if not result.isError():
                            self.get_logger().info("Successfully wrote E-stop assertion to safety OpenPLC")
                            return
                        else:
                            self.get_logger().error(f"Modbus write error: {result}")
                except Exception as exc:
                    self.get_logger().warning(f"Exception writing E-stop to PLC: {exc}")
            time.sleep(0.05)
        self.get_logger().error("Failed to write E-stop assertion to OpenPLC after 3 attempts")

    def _poll_plc_state(self) -> None:
        if not self._connect_to_plc():
            return
        
        safety_state = None
        last_fault_code = None
        
        try:
            with self._safety_lock:
                # Read 3 registers starting at address 10 (%MW10 to %MW12: safety_state, ack_counter, last_fault_code)
                result = self._client.read_holding_registers(10, 3)
                if not result.isError():
                    safety_state = int(result.registers[0])
                    last_fault_code = int(result.registers[2])
                    # Publish the state
                    msg = UInt8()
                    msg.data = safety_state
                    self._state_pub.publish(msg)
                else:
                    self.get_logger().debug(f"Modbus read error: {result}")
        except Exception as exc:
            self.get_logger().debug(f"Exception polling safety OpenPLC state: {exc}")
            # Reset client socket to force reconnection on next poll
            with self._safety_lock:
                if self._client:
                    try:
                        self._client.close()
                    except Exception:
                        pass
                    self._client = None
            return

        # Synchronize safety registers to Production OpenPLC
        if safety_state is not None:
            if (safety_state != self._last_synchronized_state or 
                last_fault_code != self._last_synchronized_fault):
                
                # Update local cache immediately to prevent spawning multiple threads for the same change
                self._last_synchronized_state = safety_state
                self._last_synchronized_fault = last_fault_code
                
                # Spawn background thread to synchronize with Production PLC
                t = threading.Thread(
                    target=self._sync_to_prod_plc,
                    args=(safety_state, last_fault_code),
                    daemon=True
                )
                t.start()

    def _sync_to_prod_plc(self, safety_state: int, last_fault_code: int) -> None:
        if self._connect_to_prod_plc():
            try:
                with self._prod_lock:
                    slow_mode = 1 if safety_state == 1 else 0
                    
                    # Write to %MW10 (address 1034), %MW12 (address 1036), and %MW4 (address 1028) on Production OpenPLC
                    self._prod_client.write_register(1034, safety_state)
                    self._prod_client.write_register(1036, last_fault_code)
                    self._prod_client.write_register(1028, slow_mode)
                    
                    estop_val = True if safety_state == 2 else False
                    safe_state_req = True if safety_state in (1, 2) else False
                    
                    self._prod_client.write_coil(5, estop_val)
                    self._prod_client.write_coil(6, safe_state_req)
                    
                self.get_logger().info(f"Synchronized state to Production PLC: state={safety_state}, fault={last_fault_code}")
            except Exception as exc:
                self.get_logger().warning(f"Exception synchronizing state to Production OpenPLC: {exc}")
                # Reset production client to force reconnect next time
                with self._prod_lock:
                    if self._prod_client:
                        try:
                            self._prod_client.close()
                        except Exception:
                            pass
                        self._prod_client = None

    def _poll_loop(self) -> None:
        while rclpy.ok() and not self._stop_polling.is_set():
            try:
                self._poll_plc_state()
            except Exception as exc:
                self.get_logger().debug(f"Poll loop error: {exc}")
            time.sleep(self._poll_period)

    def close(self) -> None:
        try:
            self._stop_polling.set()
            if hasattr(self, "_poll_thread") and self._poll_thread.is_alive():
                self._poll_thread.join(timeout=1.0)
        except Exception:
            pass
        with self._safety_lock:
            if self._client:
                try:
                    self._client.close()
                except Exception:
                    pass
                self._client = None
        with self._prod_lock:
            if self._prod_client:
                try:
                    self._prod_client.close()
                except Exception:
                    pass
                self._prod_client = None


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--plc-host", default=os.environ.get("LAB_PLC_HOST", "127.0.0.1"))
    p.add_argument("--plc-port", type=int, default=int(os.environ.get("LAB_PLC_PORT", "503")))
    p.add_argument("--log-level", default=os.environ.get("LAB_LOG_LEVEL", "INFO"))
    args = p.parse_args(argv)
    
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    
    rclpy.init(args=sys.argv)
    node = SafetyBridgeNode(args.plc_host, args.plc_port)
    
    def _shutdown(*_a) -> None:
        LOG.info("Shutdown requested")
        if rclpy.ok():
            rclpy.shutdown()
            
    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    
    rc = 0
    try:
        rclpy.spin(node)
    except Exception as exc:
        LOG.error(f"safety_bridge crashed: {exc}", exc_info=True)
        rc = 1
    finally:
        node.close()
        node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()
        LOG.info(f"safety_bridge exiting (rc={rc})")
    return rc


if __name__ == "__main__":
    sys.exit(main())
