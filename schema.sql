CREATE TABLE IF NOT EXISTS directory_users (
  username text PRIMARY KEY,
  display_name text NOT NULL,
  email text NOT NULL DEFAULT '',
  department text NOT NULL DEFAULT '',
  factory text NOT NULL DEFAULT '',
  title text NOT NULL DEFAULT '',
  groups jsonb NOT NULL DEFAULT '[]'::jsonb,
  enabled boolean NOT NULL DEFAULT true,
  synced_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS directory_servers (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  host text NOT NULL,
  port integer NOT NULL,
  security text NOT NULL CHECK (security IN ('ldaps','starttls')),
  bind_dn text NOT NULL,
  encrypted_password text NOT NULL,
  base_dn text NOT NULL,
  user_filter text NOT NULL,
  group_filter text NOT NULL,
  username_attribute text NOT NULL DEFAULT 'sAMAccountName',
  display_attribute text NOT NULL DEFAULT 'displayName',
  email_attribute text NOT NULL DEFAULT 'mail',
  department_attribute text NOT NULL DEFAULT 'department',
  enabled boolean NOT NULL DEFAULT true,
  last_sync timestamptz,
  last_error text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS directory_objects (
  server_id uuid NOT NULL REFERENCES directory_servers(id) ON DELETE CASCADE,
  object_type text NOT NULL CHECK (object_type IN ('user','group')),
  object_id text NOT NULL,
  username text NOT NULL DEFAULT '',
  display_name text NOT NULL DEFAULT '',
  email text NOT NULL DEFAULT '',
  department text NOT NULL DEFAULT '',
  factory text NOT NULL DEFAULT '',
  title text NOT NULL DEFAULT '',
  groups jsonb NOT NULL DEFAULT '[]'::jsonb,
  enabled boolean NOT NULL DEFAULT true,
  synced_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(server_id, object_type, object_id)
);
CREATE INDEX IF NOT EXISTS directory_objects_name_idx ON directory_objects(server_id, object_type, display_name);
CREATE TABLE IF NOT EXISTS app_state (
  key text PRIMARY KEY,
  value jsonb NOT NULL DEFAULT '[]'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS tickets (
  id text PRIMARY KEY,
  kind text NOT NULL,
  username text NOT NULL,
  display_name text NOT NULL,
  department text NOT NULL DEFAULT '',
  factory text NOT NULL DEFAULT '',
  client_ip inet,
  primary_category text NOT NULL,
  sub_category text NOT NULL,
  description text NOT NULL,
  material text NOT NULL DEFAULT '',
  attachments jsonb NOT NULL DEFAULT '[]'::jsonb,
  assigned_to text NOT NULL DEFAULT 'Unassigned',
  status text NOT NULL DEFAULT 'Open' CHECK (status IN ('Open','In progress','Resolved','Closed')),
  eta timestamptz,
  note text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS tickets_created_at_idx ON tickets(created_at DESC);
CREATE INDEX IF NOT EXISTS tickets_username_idx ON tickets(username);
CREATE TABLE IF NOT EXISTS ticket_events (
  id bigserial PRIMARY KEY,
  ticket_id text NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
  actor text NOT NULL,
  event_type text NOT NULL,
  detail text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS login_attempts (
  client_ip inet PRIMARY KEY,
  failures integer NOT NULL DEFAULT 0,
  blocked_until timestamptz
);
