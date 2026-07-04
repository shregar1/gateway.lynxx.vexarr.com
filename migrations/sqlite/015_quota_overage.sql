-- Persist paid-tier overage call counts so they survive restarts.
--
-- Previously the overage counter lived only in memory: flush() wrote
-- calls_total + calls_rejected but never the overage, and the table had no
-- column for it, so every redeploy/crash silently reset billable overage to
-- zero. This adds the column; the quota tracker now persists and reloads it.
ALTER TABLE quota_usage ADD COLUMN calls_overage INTEGER NOT NULL DEFAULT 0;
