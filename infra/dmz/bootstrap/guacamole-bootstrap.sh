#!/bin/sh
set -eu

MIN_PASSWORD_LENGTH=16

require_secret() {
    name="$1"
    value="$2"
    if [ "${#value}" -lt "$MIN_PASSWORD_LENGTH" ]; then
        echo "${name} must be set and contain at least ${MIN_PASSWORD_LENGTH} characters" >&2
        exit 1
    fi
}

require_secret POSTGRES_PASSWORD "$PGPASSWORD"
require_secret OT_RDP_PASSWORD "$OT_RDP_PASSWORD"
require_secret GUAC_ADMIN_PASSWORD "$GUAC_ADMIN_PASSWORD"
require_secret GUAC_OPERATOR_PASSWORD "$GUAC_OPERATOR_PASSWORD"
require_secret GUAC_VENDOR_PASSWORD "$GUAC_VENDOR_PASSWORD"
require_secret GUAC_AUDITOR_PASSWORD "$GUAC_AUDITOR_PASSWORD"

# psql reads secret values from its environment, not its command line. The
# :'<name>' syntax below emits a properly escaped SQL string literal.
psql -v ON_ERROR_STOP=1 <<'SQL'
\getenv rdp_password OT_RDP_PASSWORD
\getenv guac_admin_password GUAC_ADMIN_PASSWORD
\getenv guac_operator_password GUAC_OPERATOR_PASSWORD
\getenv guac_vendor_password GUAC_VENDOR_PASSWORD
\getenv guac_auditor_password GUAC_AUDITOR_PASSWORD

CREATE EXTENSION IF NOT EXISTS pgcrypto;

INSERT INTO guacamole_entity (name, type)
VALUES
    ('guacadmin', 'USER'),
    ('operator', 'USER'),
    ('vendor', 'USER'),
    ('auditor', 'USER')
ON CONFLICT DO NOTHING;

WITH requested(account_name, account_password) AS (
    VALUES
        ('guacadmin', :'guac_admin_password'::text),
        ('operator', :'guac_operator_password'::text),
        ('vendor', :'guac_vendor_password'::text),
        ('auditor', :'guac_auditor_password'::text)
), salted AS (
    SELECT e.entity_id, r.account_password, gen_random_bytes(32) AS salt
    FROM requested r
    JOIN guacamole_entity e
      ON e.name = r.account_name AND e.type = 'USER'
)
INSERT INTO guacamole_user (
    entity_id, password_hash, password_salt, password_date, disabled, expired
)
SELECT
    entity_id,
    digest(convert_to(account_password || upper(encode(salt, 'hex')), 'UTF8'), 'sha256'),
    salt,
    CURRENT_TIMESTAMP,
    false,
    false
FROM salted
ON CONFLICT (entity_id) DO UPDATE SET
    password_hash = EXCLUDED.password_hash,
    password_salt = EXCLUDED.password_salt,
    password_date = EXCLUDED.password_date,
    disabled = false,
    expired = false;

INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value)
SELECT connection_id, 'password', :'rdp_password'
FROM guacamole_connection
WHERE connection_name IN (
    'OT Gazebo Desktop (RDP)',
    'Vendor Read-Only View (RDP)',
    'OT-ReadOnly',
    'OT-Maintenance',
    'Historian Read-Only (HTTP)'
)
ON CONFLICT (connection_id, parameter_name) DO UPDATE SET
    parameter_value = EXCLUDED.parameter_value;

INSERT INTO guacamole_system_permission (entity_id, permission)
SELECT e.entity_id, p.permission::guacamole_system_permission_type
FROM guacamole_entity e
CROSS JOIN (VALUES
    ('CREATE_CONNECTION'),
    ('CREATE_CONNECTION_GROUP'),
    ('CREATE_SHARING_PROFILE'),
    ('CREATE_USER'),
    ('CREATE_USER_GROUP'),
    ('ADMINISTER')
) AS p(permission)
WHERE e.name = 'guacadmin' AND e.type = 'USER'
ON CONFLICT DO NOTHING;

INSERT INTO guacamole_user_permission (entity_id, affected_user_id, permission)
SELECT e.entity_id, u.user_id, p.permission::guacamole_object_permission_type
FROM guacamole_entity e
JOIN guacamole_user u ON u.entity_id = e.entity_id
CROSS JOIN (VALUES ('READ'), ('UPDATE'), ('ADMINISTER')) AS p(permission)
WHERE e.name = 'guacadmin' AND e.type = 'USER'
ON CONFLICT DO NOTHING;

INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission)
SELECT e.entity_id, c.connection_id, 'READ'
FROM guacamole_entity e
CROSS JOIN guacamole_connection c
WHERE e.name = 'guacadmin' AND e.type = 'USER'
ON CONFLICT DO NOTHING;

INSERT INTO guacamole_connection_group_permission (entity_id, connection_group_id, permission)
SELECT e.entity_id, g.connection_group_id, 'READ'
FROM guacamole_entity e
CROSS JOIN guacamole_connection_group g
WHERE e.name = 'guacadmin' AND e.type = 'USER'
ON CONFLICT DO NOTHING;
SQL

echo "Guacamole credentials and connection passwords configured from environment"
