# =====================================================================
# Lab Modbus feature emitter.
#
# Produces a TSV-friendly "modbus_features.log" with one row per Modbus
# message containing the exact features Stage 2's ML pipeline consumes:
#
#   ts          double   timestamp (epoch float seconds)
#   uid         string   connection UID (joins to conn.log)
#   src_ip      addr
#   dst_ip      addr
#   src_port    port
#   dst_port    port
#   func_code   count    Modbus function code
#   is_request  bool
#   address     count    register / coil base address (0 if unknown)
#   quantity    count    quantity field (0 if unknown)
#   exception   bool     1 if exception response
#   ot_origin   bool     true if src_ip is in 192.168.10.0/24
#
# Stage 2 reads /var/lab/log/zeek/current/modbus_features.log on VM-SEC.
# =====================================================================

module ModbusFeatures;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:         time    &log;
        uid:        string  &log;
        src_ip:     addr    &log;
        dst_ip:     addr    &log;
        src_port:   port    &log;
        dst_port:   port    &log;
        func_code:  count   &log;
        is_request: bool    &log;
        address:    count   &log &default=0;
        quantity:   count   &log &default=0;
        exception:  bool    &log &default=F;
        ot_origin:  bool    &log;
    };

    global log_modbus_features: event(rec: Info);
}

event zeek_init() &priority=5
{
    Log::create_stream(LOG, [
        $columns=Info,
        $ev=log_modbus_features,
        $path="modbus_features"
    ]);
}

# ---------- main hook ----------------------------------------------------
event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
{
    local rec: Info;
    rec$ts         = network_time();
    rec$uid        = c$uid;
    rec$src_ip     = c$id$orig_h;
    rec$dst_ip     = c$id$resp_h;
    rec$src_port   = c$id$orig_p;
    rec$dst_port   = c$id$resp_p;
    rec$func_code  = headers$function_code;
    rec$is_request = is_orig;
    rec$exception  = headers$function_code >= 0x80;
    rec$ot_origin  = c$id$orig_h in 192.168.10.0/24;
    Log::write(ModbusFeatures::LOG, rec);
}

# Read/Write Single Register/Coil events: capture address + quantity.
event modbus_read_holding_registers_request(c: connection, headers: ModbusHeaders,
                                            start_address: count, quantity: count)
{
    local rec: Info;
    rec$ts = network_time(); rec$uid = c$uid;
    rec$src_ip = c$id$orig_h; rec$dst_ip = c$id$resp_h;
    rec$src_port = c$id$orig_p; rec$dst_port = c$id$resp_p;
    rec$func_code = 3; rec$is_request = T;
    rec$address = start_address; rec$quantity = quantity;
    rec$exception = F;
    rec$ot_origin = c$id$orig_h in 192.168.10.0/24;
    Log::write(ModbusFeatures::LOG, rec);
}

event modbus_write_single_register_request(c: connection, headers: ModbusHeaders,
                                           address: count, value: count)
{
    local rec: Info;
    rec$ts = network_time(); rec$uid = c$uid;
    rec$src_ip = c$id$orig_h; rec$dst_ip = c$id$resp_h;
    rec$src_port = c$id$orig_p; rec$dst_port = c$id$resp_p;
    rec$func_code = 6; rec$is_request = T;
    rec$address = address; rec$quantity = 1;
    rec$exception = F;
    rec$ot_origin = c$id$orig_h in 192.168.10.0/24;
    Log::write(ModbusFeatures::LOG, rec);
}

event modbus_write_single_coil_request(c: connection, headers: ModbusHeaders,
                                       address: count, value: bool)
{
    local rec: Info;
    rec$ts = network_time(); rec$uid = c$uid;
    rec$src_ip = c$id$orig_h; rec$dst_ip = c$id$resp_h;
    rec$src_port = c$id$orig_p; rec$dst_port = c$id$resp_p;
    rec$func_code = 5; rec$is_request = T;
    rec$address = address; rec$quantity = 1;
    rec$exception = F;
    rec$ot_origin = c$id$orig_h in 192.168.10.0/24;
    Log::write(ModbusFeatures::LOG, rec);
}
