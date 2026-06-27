ALTER TABLE services ADD COLUMN hide_patterns JSONB DEFAULT '[]'::jsonb;
