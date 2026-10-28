export const statements = [
  `CREATE TABLE IF NOT EXISTS "user" (
    "id" text PRIMARY KEY,
    "name" text NOT NULL,
    "email" text NOT NULL UNIQUE,
    "emailVerified" boolean NOT NULL DEFAULT false,
    "image" text,
    "createdAt" timestamptz NOT NULL DEFAULT now(),
    "updatedAt" timestamptz NOT NULL DEFAULT now()
  )`,
  `CREATE TABLE IF NOT EXISTS "session" (
    "id" text PRIMARY KEY,
    "expiresAt" timestamptz NOT NULL,
    "token" text NOT NULL UNIQUE,
    "createdAt" timestamptz NOT NULL DEFAULT now(),
    "updatedAt" timestamptz NOT NULL DEFAULT now(),
    "ipAddress" text,
    "userAgent" text,
    "userId" text NOT NULL REFERENCES "user"("id") ON DELETE CASCADE
  )`,
  `CREATE INDEX IF NOT EXISTS session_user_id_idx ON "session" ("userId")`,
  `CREATE TABLE IF NOT EXISTS "account" (
    "id" text PRIMARY KEY,
    "accountId" text NOT NULL,
    "providerId" text NOT NULL,
    "userId" text NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
    "accessToken" text,
    "refreshToken" text,
    "idToken" text,
    "accessTokenExpiresAt" timestamptz,
    "refreshTokenExpiresAt" timestamptz,
    "scope" text,
    "password" text,
    "createdAt" timestamptz NOT NULL DEFAULT now(),
    "updatedAt" timestamptz NOT NULL DEFAULT now()
  )`,
  `CREATE INDEX IF NOT EXISTS account_user_id_idx ON "account" ("userId")`,
  `CREATE TABLE IF NOT EXISTS "verification" (
    "id" text PRIMARY KEY,
    "identifier" text NOT NULL,
    "value" text NOT NULL,
    "expiresAt" timestamptz NOT NULL,
    "createdAt" timestamptz NOT NULL DEFAULT now(),
    "updatedAt" timestamptz NOT NULL DEFAULT now()
  )`,
  `CREATE INDEX IF NOT EXISTS verification_identifier_idx ON "verification" ("identifier")`,
  `CREATE TABLE IF NOT EXISTS "rateLimit" (
    "id" text PRIMARY KEY,
    "key" text NOT NULL UNIQUE,
    "count" integer NOT NULL,
    "lastRequest" bigint NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS folder (
    id text PRIMARY KEY,
    owner_user_id text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    name text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('personal', 'project')),
    github_repo text,
    created_at timestamptz NOT NULL DEFAULT now()
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS folder_one_personal ON folder (owner_user_id) WHERE kind = 'personal'`,
  `CREATE TABLE IF NOT EXISTS item (
    id text PRIMARY KEY,
    folder_id text NOT NULL REFERENCES folder(id) ON DELETE CASCADE,
    created_by text NOT NULL REFERENCES "user"(id),
    name text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('api_key', 'ssh_key')),
    wrapped_dek text NOT NULL,
    dek_iv text NOT NULL,
    dek_tag text NOT NULL,
    ciphertext text NOT NULL,
    iv text NOT NULL,
    tag text NOT NULL,
    fingerprint text,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS item_folder_name_active ON item (folder_id, name) WHERE revoked_at IS NULL`,
  `CREATE TABLE IF NOT EXISTS share (
    id text PRIMARY KEY,
    resource_type text NOT NULL CHECK (resource_type IN ('folder', 'item')),
    resource_id text NOT NULL,
    grantee_email text NOT NULL,
    permission text NOT NULL CHECK (permission IN ('use', 'admin')),
    created_by text NOT NULL REFERENCES "user"(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (resource_type, resource_id, grantee_email)
  )`,
  `CREATE TABLE IF NOT EXISTS agent_token (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    name text NOT NULL,
    token_hash text NOT NULL UNIQUE,
    token_prefix text NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz
  )`,
  `CREATE TABLE IF NOT EXISTS access_request (
    id text PRIMARY KEY,
    requester_user_id text NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    agent_token_id text REFERENCES agent_token(id) ON DELETE SET NULL,
    folder_id text REFERENCES folder(id) ON DELETE SET NULL,
    kind text NOT NULL CHECK (kind IN ('item', 'env_bundle')),
    purpose text NOT NULL,
    status text NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'consumed', 'expired')),
    wrap_public_key text,
    grant_hash text UNIQUE,
    grant_wrapped_dek text,
    grant_dek_iv text,
    grant_dek_tag text,
    grant_ciphertext text,
    grant_iv text,
    grant_tag text,
    grant_expires_at timestamptz,
    consumed_at timestamptz,
    decided_by text REFERENCES "user"(id) ON DELETE SET NULL,
    decided_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
  )`,
  `CREATE TABLE IF NOT EXISTS access_request_item (
    request_id text NOT NULL REFERENCES access_request(id) ON DELETE CASCADE,
    item_id text NOT NULL REFERENCES item(id) ON DELETE CASCADE,
    PRIMARY KEY (request_id, item_id)
  )`,
  `CREATE TABLE IF NOT EXISTS env_binding (
    id text PRIMARY KEY,
    folder_id text NOT NULL REFERENCES folder(id) ON DELETE CASCADE,
    item_id text NOT NULL REFERENCES item(id) ON DELETE CASCADE,
    env_key text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (folder_id, env_key)
  )`,
  `CREATE TABLE IF NOT EXISTS audit_event (
    id text PRIMARY KEY,
    actor_user_id text,
    action text NOT NULL,
    resource_type text,
    resource_id text,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    ip text,
    user_agent text,
    created_at timestamptz NOT NULL DEFAULT now()
  )`,
  `CREATE INDEX IF NOT EXISTS audit_event_created_idx ON audit_event (created_at DESC)`,
  `CREATE TABLE IF NOT EXISTS app_rate_limit (
    bucket text PRIMARY KEY,
    count integer NOT NULL,
    expires_at timestamptz NOT NULL
  )`,
];
