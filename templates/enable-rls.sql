-- Enable Row Level Security on a table, then add a policy.
-- Without RLS, the public anon key can read/write this table directly —
-- this is the #1 cause of drained/defaced Supabase-backed apps.

ALTER TABLE your_table_name ENABLE ROW LEVEL SECURITY;

-- Example: users can only read their own rows.
CREATE POLICY "Users can read their own rows"
  ON your_table_name
  FOR SELECT
  USING (auth.uid() = user_id);

-- Repeat ALTER TABLE ... ENABLE ROW LEVEL SECURITY for every table —
-- there are no exceptions. A table with RLS enabled but no policies
-- denies all access by default, which is a safe starting point.
