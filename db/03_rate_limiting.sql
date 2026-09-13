-- Chunk 9, §12 resolved: per-app rate limiting/quotas.
-- NULL = unlimited (the default for every existing/new App).
ALTER TABLE apps ADD COLUMN rate_limit_rpm INT;
