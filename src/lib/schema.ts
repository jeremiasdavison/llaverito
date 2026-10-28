import { relations } from "drizzle-orm";
import {
  bigint,
  boolean,
  index,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
} from "drizzle-orm/pg-core";

const ts = (name: string) => timestamp(name, { withTimezone: true, mode: "date" });

export const user = pgTable("user", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  email: text("email").notNull().unique(),
  emailVerified: boolean("emailVerified").notNull().default(false),
  image: text("image"),
  createdAt: ts("createdAt").notNull().defaultNow(),
  updatedAt: ts("updatedAt").notNull().defaultNow(),
});

export const session = pgTable(
  "session",
  {
    id: text("id").primaryKey(),
    expiresAt: ts("expiresAt").notNull(),
    token: text("token").notNull().unique(),
    createdAt: ts("createdAt").notNull().defaultNow(),
    updatedAt: ts("updatedAt").notNull().defaultNow(),
    ipAddress: text("ipAddress"),
    userAgent: text("userAgent"),
    userId: text("userId")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
  },
  (table) => [index("session_user_id_idx").on(table.userId)],
);

export const account = pgTable(
  "account",
  {
    id: text("id").primaryKey(),
    accountId: text("accountId").notNull(),
    providerId: text("providerId").notNull(),
    userId: text("userId")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    accessToken: text("accessToken"),
    refreshToken: text("refreshToken"),
    idToken: text("idToken"),
    accessTokenExpiresAt: ts("accessTokenExpiresAt"),
    refreshTokenExpiresAt: ts("refreshTokenExpiresAt"),
    scope: text("scope"),
    password: text("password"),
    createdAt: ts("createdAt").notNull().defaultNow(),
    updatedAt: ts("updatedAt").notNull().defaultNow(),
  },
  (table) => [index("account_user_id_idx").on(table.userId)],
);

export const verification = pgTable(
  "verification",
  {
    id: text("id").primaryKey(),
    identifier: text("identifier").notNull(),
    value: text("value").notNull(),
    expiresAt: ts("expiresAt").notNull(),
    createdAt: ts("createdAt").notNull().defaultNow(),
    updatedAt: ts("updatedAt").notNull().defaultNow(),
  },
  (table) => [index("verification_identifier_idx").on(table.identifier)],
);

export const rateLimit = pgTable("rateLimit", {
  id: text("id").primaryKey(),
  key: text("key").notNull().unique(),
  count: integer("count").notNull(),
  lastRequest: bigint("lastRequest", { mode: "number" }).notNull(),
});

export const userRelations = relations(user, ({ many }) => ({
  sessions: many(session),
  accounts: many(account),
}));

export const sessionRelations = relations(session, ({ one }) => ({
  user: one(user, { fields: [session.userId], references: [user.id] }),
}));

export const accountRelations = relations(account, ({ one }) => ({
  user: one(user, { fields: [account.userId], references: [user.id] }),
}));

export const folder = pgTable("folder", {
  id: text("id").primaryKey(),
  ownerUserId: text("owner_user_id")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  kind: text("kind").$type<"personal" | "project">().notNull(),
  githubRepo: text("github_repo"),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const item = pgTable("item", {
  id: text("id").primaryKey(),
  folderId: text("folder_id")
    .notNull()
    .references(() => folder.id, { onDelete: "cascade" }),
  createdBy: text("created_by")
    .notNull()
    .references(() => user.id),
  name: text("name").notNull(),
  kind: text("kind").$type<"api_key" | "ssh_key">().notNull(),
  wrappedDek: text("wrapped_dek").notNull(),
  dekIv: text("dek_iv").notNull(),
  dekTag: text("dek_tag").notNull(),
  ciphertext: text("ciphertext").notNull(),
  iv: text("iv").notNull(),
  tag: text("tag").notNull(),
  fingerprint: text("fingerprint"),
  revokedAt: ts("revoked_at"),
  createdAt: ts("created_at").notNull().defaultNow(),
  updatedAt: ts("updated_at").notNull().defaultNow(),
});

export const share = pgTable(
  "share",
  {
    id: text("id").primaryKey(),
    resourceType: text("resource_type").$type<"folder" | "item">().notNull(),
    resourceId: text("resource_id").notNull(),
    granteeEmail: text("grantee_email").notNull(),
    permission: text("permission").$type<"use" | "admin">().notNull(),
    createdBy: text("created_by")
      .notNull()
      .references(() => user.id),
    createdAt: ts("created_at").notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("share_target").on(table.resourceType, table.resourceId, table.granteeEmail),
  ],
);

export const agentToken = pgTable("agent_token", {
  id: text("id").primaryKey(),
  userId: text("user_id")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  tokenHash: text("token_hash").notNull().unique(),
  tokenPrefix: text("token_prefix").notNull(),
  revokedAt: ts("revoked_at"),
  createdAt: ts("created_at").notNull().defaultNow(),
  lastUsedAt: ts("last_used_at"),
});

export const accessRequest = pgTable("access_request", {
  id: text("id").primaryKey(),
  requesterUserId: text("requester_user_id")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
  agentTokenId: text("agent_token_id").references(() => agentToken.id, { onDelete: "set null" }),
  folderId: text("folder_id").references(() => folder.id, { onDelete: "set null" }),
  kind: text("kind").$type<"item" | "env_bundle">().notNull(),
  purpose: text("purpose").notNull(),
  status: text("status")
    .$type<"pending" | "approved" | "denied" | "consumed" | "expired">()
    .notNull(),
  wrapPublicKey: text("wrap_public_key"),
  grantHash: text("grant_hash").unique(),
  grantWrappedDek: text("grant_wrapped_dek"),
  grantDekIv: text("grant_dek_iv"),
  grantDekTag: text("grant_dek_tag"),
  grantCiphertext: text("grant_ciphertext"),
  grantIv: text("grant_iv"),
  grantTag: text("grant_tag"),
  grantExpiresAt: ts("grant_expires_at"),
  consumedAt: ts("consumed_at"),
  decidedBy: text("decided_by").references(() => user.id, { onDelete: "set null" }),
  decidedAt: ts("decided_at"),
  createdAt: ts("created_at").notNull().defaultNow(),
});

export const accessRequestItem = pgTable(
  "access_request_item",
  {
    requestId: text("request_id")
      .notNull()
      .references(() => accessRequest.id, { onDelete: "cascade" }),
    itemId: text("item_id")
      .notNull()
      .references(() => item.id, { onDelete: "cascade" }),
  },
  (table) => [uniqueIndex("access_request_item_pk").on(table.requestId, table.itemId)],
);

export const envBinding = pgTable(
  "env_binding",
  {
    id: text("id").primaryKey(),
    folderId: text("folder_id")
      .notNull()
      .references(() => folder.id, { onDelete: "cascade" }),
    itemId: text("item_id")
      .notNull()
      .references(() => item.id, { onDelete: "cascade" }),
    envKey: text("env_key").notNull(),
    createdAt: ts("created_at").notNull().defaultNow(),
  },
  (table) => [uniqueIndex("env_binding_key").on(table.folderId, table.envKey)],
);

export const auditEvent = pgTable(
  "audit_event",
  {
    id: text("id").primaryKey(),
    actorUserId: text("actor_user_id"),
    action: text("action").notNull(),
    resourceType: text("resource_type"),
    resourceId: text("resource_id"),
    metadata: jsonb("metadata").$type<Record<string, string | number | boolean | null>>().notNull(),
    ip: text("ip"),
    userAgent: text("user_agent"),
    createdAt: ts("created_at").notNull().defaultNow(),
  },
  (table) => [index("audit_event_created_idx").on(table.createdAt)],
);

export const appRateLimit = pgTable("app_rate_limit", {
  bucket: text("bucket").primaryKey(),
  count: integer("count").notNull(),
  expiresAt: ts("expires_at").notNull(),
});

export const authSchema = { user, session, account, verification, rateLimit };

export const schema = {
  user,
  session,
  account,
  verification,
  rateLimit,
  userRelations,
  sessionRelations,
  accountRelations,
  folder,
  item,
  share,
  agentToken,
  accessRequest,
  accessRequestItem,
  envBinding,
  auditEvent,
  appRateLimit,
};
