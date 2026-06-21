# =====================================================================
# Site-local Zeek policy for the Robotics Security Platform lab.
#
# Loaded by zeekctl after the base policy. Enables ICS protocol analyzers
# and the lab-specific feature emitter that feeds Stage 2's ML pipeline.
# =====================================================================

# ---------- 1. Standard policy bundles --------------------------------
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/ssl
@load base/protocols/http

# Industrial protocols (shipped with Zeek 6.x).
@load base/protocols/modbus
@load base/protocols/dnp3
# EtherNet/IP and S7 are community-maintained packages; they may not be
# present on a fresh install. Load with @if-guard so missing packages
# do not break Zeek startup.
@ifdef ( EtherNet_IP )
@load base/protocols/enip
@endif

# ---------- 2. Lab-specific feature emitter ---------------------------
@load ./modbus-features.zeek
@load ./dnp3-features.zeek
@load ./opcua-features.zeek

# ---------- 3. Notice output --------------------------------------------
redef Notice::default_suppression_interval = 1 hr;

# Always log conn.log and modbus.log even if Zeek's defaults change.
redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;
redef ignore_checksums = T;

# ---------- 4. Network ranges --------------------------------------------
# So Zeek's notice and origin scripts know which IPs are "local" to OT.
redef Site::local_nets = {
    192.168.10.0/24,    # OT zone
    192.168.20.0/24,    # IT zone
    192.168.30.0/24,    # DMZ
    192.168.40.0/24     # mgmt
};

# ---------- 5. Notice escalation: alert on Modbus writes from outside OT
# Notice type must be declared before the event handler that emits it.
redef enum Notice::Type += {
    Modbus_Write_From_Outside_OT,
};

event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool) &priority=-5
{
    if ( ! is_orig )
        return;

    # Function codes that *write*: 5, 6, 15, 16, 22, 23.
    local writing_fcs: set[count] = { 5, 6, 15, 16, 22, 23 };
    if ( headers$function_code !in writing_fcs )
        return;

    # If the source is not in the OT zone, this is suspicious.
    if ( c$id$orig_h !in 192.168.10.0/24 )
    {
        NOTICE([$note=Modbus_Write_From_Outside_OT,
                $msg=fmt("Modbus FC=%d write from %s to %s",
                         headers$function_code, c$id$orig_h, c$id$resp_h),
                $conn=c,
                $identifier=cat(c$id$orig_h, headers$function_code)]);
    }
}
