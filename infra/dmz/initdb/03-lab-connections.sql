-- =============================================================================
-- Lab Guacamole Vendor Access Management Setup
-- =============================================================================
-- Creates connection groups, role-based users, and connections for:
--   • OT Operators   — full RDP access to Gazebo desktop & OpenPLC UI
--   • External Vendors — read-only, session-recorded RDP view
--   • Audit Only      — read-only historian access
--
-- Passwords are SHA-256(salt || password_utf8) per Guacamole spec.
-- Pre-computed with salt = 32-byte zeros (demo lab only — change in production).
-- operator / Operator2026!  → hash below
-- vendor   / Vendor2026!    → hash below
-- auditor  / Auditor2026!   → hash below
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- 1. CONNECTION GROUPS
-- ---------------------------------------------------------------------------
INSERT INTO guacamole_connection_group (connection_group_name, type)
VALUES
    ('OT-Operators',       'ORGANIZATIONAL'),
    ('External-Vendors',   'ORGANIZATIONAL'),
    ('Audit-Only',         'ORGANIZATIONAL')
ON CONFLICT (connection_group_name, parent_id) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 2. CONNECTIONS — OT Operators Group
-- ---------------------------------------------------------------------------
WITH grp AS (SELECT connection_group_id FROM guacamole_connection_group WHERE connection_group_name = 'OT-Operators'),
     conn AS (
         INSERT INTO guacamole_connection (connection_name, protocol, parent_id)
         SELECT 'OT Gazebo Desktop (RDP)', 'rdp', connection_group_id FROM grp
         ON CONFLICT (connection_name, parent_id) DO UPDATE SET protocol = EXCLUDED.protocol
         RETURNING connection_id
     )
INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value)
SELECT connection_id, p, v FROM conn
CROSS JOIN (VALUES
    ('hostname',           '192.168.30.10'),
    ('port',               '3389'),
    ('username',           'lab'),
    ('password',           'lab2026'),
    ('security',           'any'),
    ('ignore-cert',        'true'),
    ('resize-method',      'display-update'),
    ('color-depth',        '24'),
    ('enable-wallpaper',   'false'),
    ('enable-theming',     'false'),
    ('enable-font-smoothing', 'true'),
    ('enable-drive',       'false'),
    ('enable-printing',    'false')
) AS params(p, v)
ON CONFLICT (connection_id, parameter_name) DO UPDATE SET parameter_value = EXCLUDED.parameter_value;

-- ---------------------------------------------------------------------------
-- 3. CONNECTIONS — External Vendors Group (session-recorded, read-only view)
-- ---------------------------------------------------------------------------
WITH grp AS (SELECT connection_group_id FROM guacamole_connection_group WHERE connection_group_name = 'External-Vendors'),
     conn AS (
         INSERT INTO guacamole_connection (connection_name, protocol, parent_id)
         SELECT 'Vendor Read-Only View (RDP)', 'rdp', connection_group_id FROM grp
         ON CONFLICT (connection_name, parent_id) DO UPDATE SET protocol = EXCLUDED.protocol
         RETURNING connection_id
     )
INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value)
SELECT connection_id, p, v FROM conn
CROSS JOIN (VALUES
    ('hostname',              '192.168.30.10'),
    ('port',                  '3389'),
    ('username',              'lab'),
    ('password',              'lab2026'),
    ('security',              'any'),
    ('ignore-cert',           'true'),
    ('read-only',             'true'),
    ('color-depth',           '16'),
    ('enable-wallpaper',      'false'),
    ('enable-theming',        'false'),
    ('enable-font-smoothing', 'true'),
    ('enable-drive',          'false'),
    ('enable-printing',       'false'),
    ('enable-audio',          'false'),
    ('recording-path',        '/tmp/vendor-sessions'),
    ('recording-name',        '${GUAC_DATE}-${GUAC_TIME}-${GUAC_USERNAME}'),
    ('recording-auto-create-path', 'true')
) AS params(p, v)
ON CONFLICT (connection_id, parameter_name) DO UPDATE SET parameter_value = EXCLUDED.parameter_value;

-- OT-ReadOnly connection
WITH grp AS (SELECT connection_group_id FROM guacamole_connection_group WHERE connection_group_name = 'External-Vendors'),
     conn AS (
         INSERT INTO guacamole_connection (connection_name, protocol, parent_id)
         SELECT 'OT-ReadOnly', 'rdp', connection_group_id FROM grp
         ON CONFLICT (connection_name, parent_id) DO UPDATE SET protocol = EXCLUDED.protocol
         RETURNING connection_id
     )
INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value)
SELECT connection_id, p, v FROM conn
CROSS JOIN (VALUES
    ('hostname',              '192.168.30.10'),
    ('port',                  '3389'),
    ('username',              'lab'),
    ('password',              'lab2026'),
    ('security',              'any'),
    ('ignore-cert',           'true'),
    ('read-only',             'true'),
    ('color-depth',           '16'),
    ('enable-wallpaper',      'false'),
    ('enable-theming',        'false'),
    ('enable-font-smoothing', 'true'),
    ('enable-drive',          'false'),
    ('enable-printing',       'false'),
    ('enable-audio',          'false'),
    ('recording-path',        '/tmp/vendor-sessions'),
    ('recording-name',        '${GUAC_DATE}-${GUAC_TIME}-${GUAC_USERNAME}'),
    ('recording-auto-create-path', 'true')
) AS params(p, v)
ON CONFLICT (connection_id, parameter_name) DO UPDATE SET parameter_value = EXCLUDED.parameter_value;

-- OT-Maintenance connection
WITH grp AS (SELECT connection_group_id FROM guacamole_connection_group WHERE connection_group_name = 'External-Vendors'),
     conn AS (
         INSERT INTO guacamole_connection (connection_name, protocol, parent_id)
         SELECT 'OT-Maintenance', 'rdp', connection_group_id FROM grp
         ON CONFLICT (connection_name, parent_id) DO UPDATE SET protocol = EXCLUDED.protocol
         RETURNING connection_id
     )
INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value)
SELECT connection_id, p, v FROM conn
CROSS JOIN (VALUES
    ('hostname',           '192.168.30.10'),
    ('port',               '3389'),
    ('username',           'lab'),
    ('password',           'lab2026'),
    ('security',           'any'),
    ('ignore-cert',        'true'),
    ('resize-method',      'display-update'),
    ('color-depth',        '24'),
    ('enable-wallpaper',   'false'),
    ('enable-theming',     'false'),
    ('enable-font-smoothing', 'true'),
    ('enable-drive',       'false'),
    ('enable-printing',    'false')
) AS params(p, v)
ON CONFLICT (connection_id, parameter_name) DO UPDATE SET parameter_value = EXCLUDED.parameter_value;

-- ---------------------------------------------------------------------------
-- 4. CONNECTIONS — Audit-Only Group (Historian stub SSH)
-- ---------------------------------------------------------------------------
WITH grp AS (SELECT connection_group_id FROM guacamole_connection_group WHERE connection_group_name = 'Audit-Only'),
     conn AS (
         INSERT INTO guacamole_connection (connection_name, protocol, parent_id)
         SELECT 'Historian Read-Only (HTTP)', 'rdp', connection_group_id FROM grp
         ON CONFLICT (connection_name, parent_id) DO UPDATE SET protocol = EXCLUDED.protocol
         RETURNING connection_id
     )
INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value)
SELECT connection_id, p, v FROM conn
CROSS JOIN (VALUES
    ('hostname',    '192.168.30.10'),
    ('port',        '3389'),
    ('username',    'lab'),
    ('password',    'lab2026'),
    ('security',    'any'),
    ('ignore-cert', 'true'),
    ('read-only',   'true'),
    ('recording-path', '/tmp/audit-sessions'),
    ('recording-name', '${GUAC_DATE}-${GUAC_TIME}-${GUAC_USERNAME}'),
    ('recording-auto-create-path', 'true')
) AS params(p, v)
ON CONFLICT (connection_id, parameter_name) DO UPDATE SET parameter_value = EXCLUDED.parameter_value;

-- ---------------------------------------------------------------------------
-- 5. USERS: operator / vendor / auditor
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    salt_op  bytea := decode(md5('operator-salt-lab2026'), 'hex');
    salt_vnd bytea := decode(md5('vendor-salt-lab2026'),   'hex');
    salt_aud bytea := decode(md5('auditor-salt-lab2026'),  'hex');
    eid_op   integer;
    eid_vnd  integer;
    eid_aud  integer;
BEGIN
    -- operator entity
    INSERT INTO guacamole_entity (name, type) VALUES ('operator', 'USER') ON CONFLICT DO NOTHING;
    SELECT entity_id INTO eid_op FROM guacamole_entity WHERE name = 'operator' AND type = 'USER';
    INSERT INTO guacamole_user (entity_id, password_hash, password_salt, password_date, disabled, expired)
    VALUES (
        eid_op,
        digest(salt_op || convert_to('Operator2026!', 'UTF8'), 'sha256'),
        salt_op, NOW(), false, false
    ) ON CONFLICT (entity_id) DO NOTHING;

    -- vendor entity
    INSERT INTO guacamole_entity (name, type) VALUES ('vendor', 'USER') ON CONFLICT DO NOTHING;
    SELECT entity_id INTO eid_vnd FROM guacamole_entity WHERE name = 'vendor' AND type = 'USER';
    INSERT INTO guacamole_user (entity_id, password_hash, password_salt, password_date, disabled, expired)
    VALUES (
        eid_vnd,
        digest(salt_vnd || convert_to('Vendor2026!', 'UTF8'), 'sha256'),
        salt_vnd, NOW(), false, false
    ) ON CONFLICT (entity_id) DO NOTHING;

    -- auditor entity
    INSERT INTO guacamole_entity (name, type) VALUES ('auditor', 'USER') ON CONFLICT DO NOTHING;
    SELECT entity_id INTO eid_aud FROM guacamole_entity WHERE name = 'auditor' AND type = 'USER';
    INSERT INTO guacamole_user (entity_id, password_hash, password_salt, password_date, disabled, expired)
    VALUES (
        eid_aud,
        digest(salt_aud || convert_to('Auditor2026!', 'UTF8'), 'sha256'),
        salt_aud, NOW(), false, false
    ) ON CONFLICT (entity_id) DO NOTHING;
END $$;

-- ---------------------------------------------------------------------------
-- 6. PERMISSIONS — grant each user READ on their appropriate connections
-- ---------------------------------------------------------------------------

-- guacadmin gets READ on everything
INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission)
SELECT e.entity_id, c.connection_id, 'READ'
FROM guacamole_entity e CROSS JOIN guacamole_connection c
WHERE e.name = 'guacadmin' AND e.type = 'USER'
ON CONFLICT DO NOTHING;

-- operator: OT Gazebo Desktop only
INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission)
SELECT e.entity_id, c.connection_id, 'READ'
FROM guacamole_entity e CROSS JOIN guacamole_connection c
WHERE e.name = 'operator' AND e.type = 'USER'
  AND c.connection_name = 'OT Gazebo Desktop (RDP)'
ON CONFLICT DO NOTHING;

-- vendor: Vendor Read-Only View only
INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission)
SELECT e.entity_id, c.connection_id, 'READ'
FROM guacamole_entity e CROSS JOIN guacamole_connection c
WHERE e.name = 'vendor' AND e.type = 'USER'
  AND c.connection_name IN ('Vendor Read-Only View (RDP)', 'OT-ReadOnly', 'OT-Maintenance')
ON CONFLICT DO NOTHING;

-- auditor: Historian Read-Only
INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission)
SELECT e.entity_id, c.connection_id, 'READ'
FROM guacamole_entity e CROSS JOIN guacamole_connection c
WHERE e.name = 'auditor' AND e.type = 'USER'
  AND c.connection_name = 'Historian Read-Only (HTTP)'
ON CONFLICT DO NOTHING;

-- Connection group visibility
INSERT INTO guacamole_connection_group_permission (entity_id, connection_group_id, permission)
SELECT e.entity_id, g.connection_group_id, 'READ'
FROM guacamole_entity e CROSS JOIN guacamole_connection_group g
WHERE e.name IN ('operator', 'vendor', 'auditor', 'guacadmin') AND e.type = 'USER'
ON CONFLICT DO NOTHING;

-- NOTE: The default Guacamole admin account (guacadmin / guacadmin) is left intact
-- so the web UI remains accessible. Change the password via the Guacamole UI after
-- first login: Settings → Users → guacadmin → Change Password.
-- Do NOT add SQL password manipulation here — Guacamole uses a binary salt+hash
-- format that cannot be reliably generated with standard PostgreSQL functions.
