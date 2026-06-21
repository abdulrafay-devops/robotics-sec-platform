# =====================================================================
# Lab OPC-UA feature emitter (best-effort).
#
# Produces "opcua_features.log" with minimal fields derived from conn-level
# observations so the AI/analytics layer can reason about OPC-UA exposure.
#
#   ts            time
#   uid           string
#   src_ip        addr
#   dst_ip        addr
#   service_type  string  ("opc.tcp" when port 4840 is involved)
#   node_id_count count   (0 — parser-less fallback)
#   ot_origin     bool
#
# Policy notice: flag IT→OT OPC-UA connections as violations.
# =====================================================================

module OPCUAFeatures;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:           time    &log;
        uid:          string  &log;
        src_ip:       addr    &log;
        dst_ip:       addr    &log;
        service_type: string  &log &default="opc.tcp";
        node_id_count: count  &log &default=0;
        ot_origin:    bool    &log;
    };

    global log_opcua_features: event(rec: Info);
}

redef enum Notice::Type += {
    OPCUA_IT_to_OT_Violation
};

event zeek_init() &priority=5
{
    Log::create_stream(LOG, [
        $columns=Info,
        $ev=log_opcua_features,
        $path="opcua_features"
    ]);
}

# Fallback implementation without a dedicated parser: watch for port 4840.
event connection_established(c: connection)
{
    if ( c$id$orig_p == 4840/tcp || c$id$resp_p == 4840/tcp )
    {
        local rec: Info;
        rec$ts        = network_time();
        rec$uid       = c$uid;
        rec$src_ip    = c$id$orig_h;
        rec$dst_ip    = c$id$resp_h;
        rec$ot_origin = c$id$orig_h in 192.168.10.0/24;
        Log::write(OPCUAFeatures::LOG, rec);

        # Policy: flag IT (192.168.20.0/24) → OT (192.168.10.0/24)
        if ( c$id$orig_h in 192.168.20.0/24 && c$id$resp_h in 192.168.10.0/24 )
        {
            NOTICE([$note=OPCUA_IT_to_OT_Violation,
                    $msg=fmt("OPC-UA connection from IT %s to OT %s", c$id$orig_h, c$id$resp_h),
                    $conn=c,
                    $identifier=cat(c$id$orig_h, c$id$resp_h)]);
        }
    }
}
