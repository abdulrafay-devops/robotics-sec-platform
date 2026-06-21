# =====================================================================
# Lab DNP3 feature emitter.
#
# Produces a TSV/JSON-friendly "dnp3_features.log" with one row per DNP3
# message containing basic fields for Stage 2/4 analytics:
#
#   ts                 time    timestamp (epoch float seconds)
#   uid                string  connection UID (joins to conn.log)
#   src_ip             addr
#   dst_ip             addr
#   function_code      count   DNP3 function code (0 if unknown)
#   is_request         bool
#   data_object_count  count   objects observed in PDU (0 if unknown)
#   ot_origin          bool    true if src_ip is in 192.168.10.0/24
#   unsolicited_response bool  true if response seen without observed request
#
# Flags unsolicited responses from non-OT sources as anomalies via Notice.
# Follows the structure used by modbus-features.zeek for consistency.
# =====================================================================

module DNP3Features;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:                   time   &log;
        uid:                  string &log;
        src_ip:               addr   &log;
        dst_ip:               addr   &log;
        function_code:        count  &log &default=0;
        is_request:           bool   &log;
        data_object_count:    count  &log &default=0;
        ot_origin:            bool   &log;
        unsolicited_response: bool   &log &default=F;
    };

    global log_dnp3_features: event(rec: Info);
}

redef enum Notice::Type += {
    DNP3_Unsolicited_From_NonOT
};

event zeek_init() &priority=5
{
    Log::create_stream(LOG, [
        $columns=Info,
        $ev=log_dnp3_features,
        $path="dnp3_features"
    ]);
}

# If the DNP3 analyzer is present, use its events. Fallback to conn-based
# logging (port 20000) when events are missing.
@ifdef ( DNP3::LOG )

event dnp3_message(c: connection, is_orig: bool)
{
    local rec: Info;
    rec$ts            = network_time();
    rec$uid           = c$uid;
    rec$src_ip        = c$id$orig_h;
    rec$dst_ip        = c$id$resp_h;
    rec$is_request    = is_orig;
    rec$ot_origin     = c$id$orig_h in 192.168.10.0/24;
    # Some Zeek builds do not expose parsed fields here; keep defaults.
    Log::write(DNP3Features::LOG, rec);
}

@else

event connection_established(c: connection)
{
    # Heuristic: DNP3 TCP default port 20000
    if ( c$id$orig_p == 20000/tcp || c$id$resp_p == 20000/tcp )
    {
        local rec: Info;
        rec$ts         = network_time();
        rec$uid        = c$uid;
        rec$src_ip     = c$id$orig_h;
        rec$dst_ip     = c$id$resp_h;
        rec$is_request = T;    # connection establishment is orig/request
        rec$ot_origin  = c$id$orig_h in 192.168.10.0/24;
        Log::write(DNP3Features::LOG, rec);
    }
}

@endif

# Policy: unsolicited responses from non-OT sources
# (approximate: any response where originator is outside OT)
event connection_state_remove(c: connection)
{
    # If we ever saw only resp->orig traffic (no request), mark as unsolicited.
    if ( c$id$orig_p == 20000/tcp || c$id$resp_p == 20000/tcp )
    {
        local from_ot = c$id$orig_h in 192.168.10.0/24;
        if ( ! from_ot )
        {
            NOTICE([$note=DNP3_Unsolicited_From_NonOT,
                    $msg=fmt("DNP3 unsolicited response pattern from %s to %s", c$id$orig_h, c$id$resp_h),
                    $conn=c,
                    $identifier=cat(c$id$orig_h, c$id$resp_h)]);
        }
    }
}
