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
  public_token_hash text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE tickets ADD COLUMN IF NOT EXISTS public_token_hash text;
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
