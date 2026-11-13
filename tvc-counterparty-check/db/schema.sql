-- Counterparties the business has onboarded. In a real system this table is
-- owned by your compliance tooling; the enclave only ever reads it.
--
-- Apply with:  psql "$DATABASE_URL" -f db/schema.sql

CREATE TABLE IF NOT EXISTS counterparties (
  address      TEXT PRIMARY KEY,                    -- lowercase 0x EVM address
  name         TEXT NOT NULL,
  kyb_status   TEXT NOT NULL CHECK (kyb_status IN ('pending', 'verified', 'rejected')),
  verified_at  TIMESTAMPTZ,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The enclave only reads. Give it its own role with SELECT on this table and
-- nothing else, and put that role's URL in pivotArgs. The manifest, and so the
-- URL, is visible to anyone holding a Boot Proof for the app.
--
--   CREATE ROLE counterparty_reader LOGIN PASSWORD '<generated>';
--   GRANT SELECT ON counterparties TO counterparty_reader;

-- Seed data for trying the example. Replace with your own.
INSERT INTO counterparties (address, name, kyb_status, verified_at) VALUES
  ('0x1111111111111111111111111111111111111111', 'Acme Logistics Ltd',  'verified', now() - interval '30 days'),
  ('0x2222222222222222222222222222222222222222', 'Globex Trading Co',   'pending',  NULL),
  ('0x3333333333333333333333333333333333333333', 'Initech Holdings',    'rejected', NULL)
ON CONFLICT (address) DO NOTHING;
