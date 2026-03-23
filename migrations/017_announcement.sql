-- Add announcement banner fields to server_config
ALTER TABLE server_config
  ADD COLUMN IF NOT EXISTS announcement_enabled BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS announcement_text    TEXT    NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS announcement_color   TEXT    NOT NULL DEFAULT 'gold',
  ADD COLUMN IF NOT EXISTS announcement_link    TEXT    NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS announcement_link_label TEXT NOT NULL DEFAULT '';
