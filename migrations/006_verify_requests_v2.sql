-- MekongTunnel — Extend verify_requests with reason, document_url, admin_note
-- Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang

ALTER TABLE verify_requests
  ADD COLUMN IF NOT EXISTS reason       TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS document_url TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS admin_note   TEXT NOT NULL DEFAULT '';
