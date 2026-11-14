#!/usr/bin/env node

/**
 * MarryLocal admin MCP server.
 *
 * Transport: stdio (stdout carries protocol frames, stderr carries diagnostics).
 * Backend:   existing Phoenix REST API under /api/v1/admin/*.
 *
 * Read tools execute immediately. Every mutating tool requires `confirm: true`
 * and returns a dry-run preview first. The backend records every confirmed write
 * in admin_audit_logs with source = "mcp".
 */

import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const __dirname = dirname(fileURLToPath(import.meta.url));
const envPath = resolve(__dirname, "..", ".env");

if (typeof process.loadEnvFile === "function") {
  try {
    process.loadEnvFile(envPath);
  } catch (error) {
    if (error?.code !== "ENOENT") {
      console.error(`[marrylocal-mcp] Could not load ${envPath}: ${error.message}`);
    }
  }
}

const DEBUG = String(process.env.MCP_DEBUG || "").toLowerCase() === "true";
const API_URL = String(process.env.MARRYLOCAL_API_URL || "http://localhost:4000")
  .trim()
  .replace(/\/+$/, "");
const CONFIGURED_TOKEN = clean(process.env.MARRYLOCAL_ADMIN_TOKEN);
const ADMIN_EMAIL = clean(process.env.MARRYLOCAL_ADMIN_EMAIL);
const ADMIN_PASSWORD = clean(process.env.MARRYLOCAL_ADMIN_PASSWORD);
const REQUEST_TIMEOUT_MS = 30_000;
const PREVIEW_TTL_SECONDS = 900;
const MAX_SEARCH_RESULTS = 200;

let cachedLoginToken = null;

function clean(value) {
  if (typeof value !== "string") return "";
  const trimmed = value.trim();
  return trimmed === "" ? "" : trimmed;
}

function debug(...args) {
  if (DEBUG) console.error("[marrylocal-mcp]", ...args);
}

function maskEmail(email) {
  if (!email) return null;
  const [local, domain] = String(email).split("@");
  if (!domain) return "***";
  const visible = local.slice(0, Math.min(2, local.length));
  return `${visible}${"*".repeat(Math.max(1, local.length - visible.length))}@${domain}`;
}

function maskPhone(phone) {
  if (!phone) return null;
  const digits = String(phone).replace(/\D/g, "");
  if (digits.length <= 4) return "*".repeat(Math.max(1, digits.length));
  return `${digits.slice(0, 2)}${"*".repeat(Math.max(2, digits.length - 4))}${digits.slice(-2)}`;
}

function maskDocumentNumber(value) {
  if (!value) return null;
  const text = String(value);
  if (text.length <= 4) return "*".repeat(text.length);
  return `${"*".repeat(Math.max(2, text.length - 4))}${text.slice(-4)}`;
}

function daysSince(value) {
  if (!value) return null;
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return null;
  return Math.max(0, Math.floor((Date.now() - then) / 86_400_000));
}

function hoursSince(value) {
  if (!value) return null;
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return null;
  return Math.max(0, Math.round((Date.now() - then) / 3_600_000));
}

function fullName(user) {
  if (!user) return null;
  const first = clean(user.first_name);
  const last = clean(user.last_name);
  if (!first && !last) return null;
  if (!last) return first;
  return `${first} ${last.slice(0, 1)}.`;
}

function identityVerified(user) {
  return Boolean(user?.aadhar_verified || user?.passport_verified || user?.license_verified);
}

function userSummary(user, { includeContact = false } = {}) {
  if (!user) return null;

  return {
    id: user.id,
    shortid: user.shortid ?? null,
    handle: user.user_handle ? `@${user.user_handle}` : null,
    name: fullName(user),
    age: user.age ?? null,
    gender: user.gender ?? null,
    city: user.city ?? null,
    state: user.state ?? null,
    role: user.role ?? null,
    state_status: user.user_state ?? null,
    account_age_days: daysSince(user.inserted_at),
    contact: includeContact
      ? {
          email: user.email ?? null,
          phone: user.phone_number ?? null,
        }
      : {
          email: maskEmail(user.email),
          phone: maskPhone(user.phone_number),
        },
    verification: {
      email_verified: Boolean(user.email_verified),
      identity_verified: identityVerified(user),
      aadhaar_verified: Boolean(user.aadhar_verified),
      passport_verified: Boolean(user.passport_verified),
      license_verified: Boolean(user.license_verified),
      terms_accepted: Boolean(user.terms_accepted),
    },
    peer_verification: {
      peer_verified: Boolean(user.peer_verified),
      is_peer_verifier: Boolean(user.is_peer_verifier),
      vouches_received: user.peer_vouches_received ?? 0,
      credits_remaining: user.vouch_credits_remaining ?? 0,
      available_to_vouch: Boolean(user.is_available_to_vouch),
      seed_verifier_status: user.seed_verifier_status ?? "none",
      verified_at: user.verified_at ?? null,
    },
    fees: {
      required: Boolean(user.onetime_fees_required),
      paid: Boolean(user.onetime_fees_paid),
      accepted_amount_inr: user.accepted_one_time_fees_amount ?? null,
    },
    beta_tester: Boolean(user.is_beta_tester),
  };
}

function seedCandidateSummary(user) {
  if (!user) return null;

  return {
    id: user.id,
    shortid: user.shortid ?? null,
    handle: user.user_handle ? `@${user.user_handle}` : null,
    name: fullName(user),
    email: user.email ?? null,
    phone: maskPhone(user.phone_number),
    city: user.city ?? null,
    state: user.state ?? null,
    seed_verifier_status: user.seed_verifier_status ?? null,
    peer_verified: Boolean(user.peer_verified),
    is_peer_verifier: Boolean(user.is_peer_verifier),
    vouch_credits_remaining: user.vouch_credits_remaining ?? 0,
    approved_in_city: user.approved_in_city ?? null,
    target: user.target ?? null,
    slots_remaining: user.slots_remaining ?? null,
  };
}

function kycSummary(verification, { includePreviewUrl = true } = {}) {
  const user = verification.user || {};
  const hash = verification.identity_hash || null;
  const submittedAt = verification.submitted_at ?? verification.inserted_at ?? null;
  const previewUrl = verification.preview_url || verification.document_image_url || null;

  return {
    verification_id: verification.id,
    status: verification.status,
    submitted_at: submittedAt,
    waiting_hours: hoursSince(submittedAt),
    document: {
      type: verification.document_type ?? null,
      number_masked: maskDocumentNumber(verification.document_number),
      identity_hash_prefix: hash ? `${hash.slice(0, 12)}…` : null,
      duplicate_identity_hash_warning: Boolean(verification.duplicate_identity_hash_warning),
      preview_url: includePreviewUrl ? previewUrl : null,
      preview_expires_in_seconds: previewUrl ? PREVIEW_TTL_SECONDS : null,
      raw_image_embedded: false,
    },
    user: {
      id: verification.user_id ?? user.id ?? null,
      shortid: user.shortid ?? null,
      handle: user.user_handle ? `@${user.user_handle}` : null,
      name: fullName(user),
      age: user.age ?? null,
      gender: user.gender ?? null,
      city: user.city ?? null,
      state: user.state ?? null,
      identity_verified: Boolean(user.verified),
      avatar_url: user.avatar_url ?? null,
    },
    rejection_reason: verification.rejection_reason ?? null,
    reviewed_at: verification.reviewed_at ?? null,
    reviewed_by_admin_email: verification.reviewed_by_admin_email ?? null,
    admin_notes: verification.admin_notes ?? null,
    operator_note: includePreviewUrl
      ? "Open preview_url in a browser for the human visual check. Never request or paste base64 image data into the model."
      : "Preview URLs were suppressed for this call.",
  };
}

async function loginForSessionToken() {
  if (cachedLoginToken) return cachedLoginToken;

  if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
    throw new Error(
      "MARRYLOCAL_ADMIN_TOKEN is empty and MARRYLOCAL_ADMIN_EMAIL/MARRYLOCAL_ADMIN_PASSWORD are not both set.",
    );
  }

  debug(`Logging in as ${ADMIN_EMAIL}`);

  const response = await fetch(`${API_URL}/api/v1/auth/login`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-Admin-Client": "mcp",
    },
    body: JSON.stringify({
      user: { email: ADMIN_EMAIL, password: ADMIN_PASSWORD },
    }),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });

  const text = await response.text();
  let payload = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = text;
  }

  if (!response.ok) {
    const message =
      payload?.message || payload?.error || `Login failed with HTTP ${response.status}`;
    throw new Error(message);
  }

  const token = payload?.data?.token;
  if (!token) throw new Error("Login succeeded but no bearer token was returned.");

  cachedLoginToken = token;
  return token;
}

async function authToken() {
  if (CONFIGURED_TOKEN) return CONFIGURED_TOKEN;
  return loginForSessionToken();
}

async function apiRequest(path, { method = "GET", query, body } = {}) {
  const url = new URL(`${API_URL}${path}`);

  for (const [key, value] of Object.entries(query || {})) {
    if (value === undefined || value === null || value === "") continue;
    url.searchParams.set(key, String(value));
  }

  const token = await authToken();
  const headers = {
    Accept: "application/json",
    Authorization: `Bearer ${token}`,
    "X-Admin-Client": "mcp",
  };

  if (body !== undefined) headers["Content-Type"] = "application/json";

  debug(`${method} ${url.pathname}${url.search}`);

  const response = await fetch(url, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });

  const text = await response.text();
  let payload = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = text;
  }

  if (!response.ok) {
    const message =
      payload?.message ||
      payload?.error ||
      (typeof payload === "string" ? payload : `HTTP ${response.status}`);
    const error = new Error(message);
    error.status = response.status;
    error.payload = payload;
    throw error;
  }

  return payload;
}

function ok(data) {
  return {
    content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
  };
}

function fail(error) {
  const status = error?.status ? ` (HTTP ${error.status})` : "";
  const details = error?.payload ? `\n${JSON.stringify(error.payload, null, 2)}` : "";

  return {
    isError: true,
    content: [
      {
        type: "text",
        text: `MarryLocal admin request failed${status}: ${error?.message || String(error)}${details}`,
      },
    ],
  };
}

function confirmationRequired(preview) {
  return ok({
    ...preview,
    confirmation_required: true,
    next_step:
      "Review the preview with the human operator. Only if they explicitly approve, call the same tool again with confirm: true.",
  });
}

const readOnly = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
};

const confirmedWrite = {
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: false,
  openWorldHint: false,
};

const GST_NOTE = "All monetary values are INR and include the recorded GST split.";

const KYC_REVIEW_CHECKLIST = `# MarryLocal KYC review checklist

Use this checklist for every identity-verification submission.

## 1. Confirm the submission is still pending
- Status must be \`pending_admin_review\`.
- If it is already \`verified\` or \`rejected\`, stop and report that the decision was already made.
- Prefer the most recent pending items first. Anything older than 24 hours is an SLA risk.

## 2. Open the document preview for the human
- Call \`list_pending_kyc\` or preview \`review_kyc_submission\` with \`confirm: false\`.
- The response includes a short-lived presigned \`preview_url\` (about 5 minutes).
- The human operator must open that URL and visually inspect the document.
- Never request, decode, or paste base64 image bytes into the model context.
- Never download the raw document yourself or send it to another service.

## 3. Verify identity alignment
- The name on the document must match the member's first and last name.
- The date of birth must match the member's age within normal document-issue tolerance.
- The gender marker must be consistent with the profile. If the document has no gender marker, rely on the name/photo and note the limitation.
- The document must not look cropped, edited, expired, or reused from another profile.

## 4. Check duplicate warnings
- \`duplicate_identity_hash_warning: true\` means the same salted identity hash exists elsewhere.
- Treat a duplicate as a probable duplicate account or stolen document. Do not approve until the human resolves it.
- The \`identity_hash_prefix\` is only a correlation aid. It is not proof of identity.
- Also inspect the member's city/state and account age for suspicious reuse patterns.

## 5. Accept only supported documents
- Passport
- Driving licence
- Document type must be one of \`passport\` or \`license\`.
- The document number must be readable and at least 4 characters.

## 6. Decide
- Approve only after the human confirms the visual check.
- Reject with a specific, actionable reason. Examples:
  - "Photo is blurred and the document number cannot be read."
  - "Name on the document does not match the profile."
  - "Document appears expired."
  - "Document is cropped and the photo page is missing."
- A rejection reason is mandatory. Never reject silently.
- Approval purges the raw document and grants the matching trust flag.

## 7. Safety rules
- Never approve because a model says the image "looks fine". A human must look.
- Never expose a member's document number, preview URL, or identity hash in public channels.
- The audit log records the admin, \`source: "mcp"\`, action, target id, and metadata.
`;

const GATE_TOGGLE_RUNBOOK = `# MarryLocal gate-toggle runbook

MarryLocal has two launch gates and one configurable annual fee. Read the current
values with \`get_admin_settings\`, preview with \`update_platform_gates\` and
\`confirm: false\`, then apply only with \`confirm: true\`.

## Verification gate
Flag: \`enforce_verification_gate\`

Turn it on only when the target city has:
- at least 50 active opposite-gender users, and
- an account base older than 7 days.

Why: the seven-day verification window must not strand early members in a city
that still has too few matches. Verify both conditions in the admin dashboard
before enabling.

Rollback: set \`enforce_verification_gate: false\`. Existing verified badges are
not removed.

## Annual fee gate
Flag: \`enforce_payment_gate\`

Turn it on only when the target city has:
- at least 250 active opposite-gender users.

Default fee: \`default_annual_fee_inr = 500\`.

Why: the fee gate is a liquidity decision. Enforcing it before a city has enough
opposite-gender supply reduces matches and increases refunds.

Rollback: set \`enforce_payment_gate: false\`. Existing paid invoices are not
refunded automatically.

## Safe procedure
1. Read current settings with \`get_admin_settings\`.
2. Confirm the launch thresholds with the human operator and cite the city data.
3. Preview with \`update_platform_gates\` and \`confirm: false\`.
4. Apply only after explicit human approval, with \`confirm: true\`.
5. Confirm the returned settings match the intended change.
6. The backend writes \`admin_audit_logs\` with \`source: "mcp"\`.
7. If the change causes a regression, re-run the tool with the previous value.
8. Never change both gates and the fee in one un-reviewed batch during launch week.

## Fee changes
- \`default_annual_fee_inr\` must be a positive integer.
- Changing the fee does not retroactively change paid invoices.
- Communicate fee changes to support before applying them.
`;

function buildServer() {
  const server = new McpServer({
    name: "marrylocal-admin",
    version: "1.0.0",
  });

  // -------------------------------------------------------------------------
  // Read-only triage tools
  // -------------------------------------------------------------------------

  server.registerTool(
    "lookup_user",
    {
      title: "Look up a MarryLocal member",
      description:
        "Exact lookup by email, @handle, phone number, shortid, or numeric id. Returns masked contact details by default, verification flags, fee status, location, and account age. Read-only.",
      inputSchema: {
        query: z
          .string()
          .min(1)
          .describe("Email address, @handle, phone number, shortid, or numeric user id."),
        include_contact: z
          .boolean()
          .default(false)
          .describe("Return full email and phone instead of masked values. Use only when operationally necessary."),
      },
      annotations: readOnly,
    },
    async ({ query, include_contact }) => {
      try {
        const payload = await apiRequest("/api/v1/admin/users/lookup", {
          query: { query },
        });

        if (!payload?.data?.user) {
          return ok({ found: false, query, message: "No member matched this exact identifier." });
        }

        return ok({
          found: true,
          query,
          pii_policy: include_contact
            ? "Full contact details were requested."
            : "Contact details are masked. Re-run with include_contact: true only if needed.",
          user: userSummary(payload.data.user, { includeContact: include_contact }),
        });
      } catch (error) {
        if (error?.status === 404) {
          return ok({ found: false, query, message: "No member matched this exact identifier." });
        }
        return fail(error);
      }
    },
  );

  server.registerTool(
    "search_users_by_location",
    {
      title: "Search members by location",
      description:
        "Lists active or inactive members filtered by state and/or city, with optional unverified_only and paid_only flags. Returns masked PII and verification/fee status. Read-only.",
      inputSchema: {
        state: z.string().min(1).optional().describe("Indian state name, case-insensitive."),
        city: z.string().min(1).optional().describe("City name, case-insensitive."),
        unverified_only: z
          .boolean()
          .default(false)
          .describe("Only members with no approved identity document."),
        paid_only: z
          .boolean()
          .default(false)
          .describe("Only members whose annual fee is marked paid."),
        limit: z.coerce
          .number()
          .int()
          .min(1)
          .max(MAX_SEARCH_RESULTS)
          .default(50)
          .describe("Maximum rows to return, capped at 200."),
        include_contact: z
          .boolean()
          .default(false)
          .describe("Return full email and phone instead of masked values."),
      },
      annotations: readOnly,
    },
    async ({ state, city, unverified_only, paid_only, limit, include_contact }) => {
      try {
        if (!clean(state) && !clean(city)) {
          return fail(
            new Error("Provide at least one of state or city. Unfiltered member dumps are disabled."),
          );
        }

        const payload = await apiRequest("/api/v1/admin/users", {
          query: {
            state,
            city,
            unverified_only,
            paid_only,
          },
        });

        const users = Array.isArray(payload?.data?.users) ? payload.data.users : [];
        const selected = users.slice(0, limit);

        return ok({
          filters: {
            state: state || null,
            city: city || null,
            unverified_only,
            paid_only,
          },
          total_matched: users.length,
          returned: selected.length,
          truncated: users.length > selected.length,
          pii_policy: include_contact
            ? "Full contact details were requested."
            : "Contact details are masked.",
          users: selected.map((user) => userSummary(user, { includeContact: include_contact })),
        });
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.registerTool(
    "list_pending_kyc",
    {
      title: "List KYC verification submissions",
      description:
        "Fetches identity-verification submissions by queue view (my_queue, all_pending, or history) with optional state/city filters. Returns member metadata, duplicate identity-hash warnings, status, reviewer details for history, and 15-minute presigned preview URLs for pending items. Never returns image bytes. Read-only.",
      inputSchema: {
        view: z
          .enum(["my_queue", "all_pending", "history"])
          .default("all_pending")
          .describe("Queue view: my assigned items, all pending, or review history."),
        state: z.string().optional().describe("Applicant state filter, case-insensitive."),
        city: z.string().optional().describe("Applicant city filter, case-insensitive."),
        older_than_hours: z.coerce
          .number()
          .int()
          .min(0)
          .optional()
          .describe("Only submissions at least this many hours old."),
        limit: z.coerce
          .number()
          .int()
          .min(1)
          .max(100)
          .default(25)
          .describe("Maximum submissions to return, capped at 100."),
        include_preview_urls: z
          .boolean()
          .default(true)
          .describe("Include 15-minute presigned document preview URLs for pending items."),
      },
      annotations: readOnly,
    },
    async ({ view, state, city, older_than_hours, limit, include_preview_urls }) => {
      try {
        const payload = await apiRequest("/api/v1/admin/verifications", {
          query: {
            view,
            state,
            city,
            per_page: limit,
          },
        });

        let verifications = Array.isArray(payload?.data?.items)
          ? payload.data.items
          : Array.isArray(payload?.data?.verifications)
            ? payload.data.verifications
            : [];

        if (Number.isInteger(older_than_hours)) {
          verifications = verifications.filter(verification => {
            const age = hoursSince(verification.submitted_at ?? verification.inserted_at);
            return age === null ? false : age >= older_than_hours;
          });
        }

        const selected = verifications.slice(0, limit);
        const meta = payload?.data?.meta ?? {};

        return ok({
          view,
          filters: {
            state: state || null,
            city: city || null,
          },
          queue_status: view === "history" ? "history" : "pending_admin_review",
          older_than_hours: older_than_hours ?? null,
          total_matched: meta.total_count ?? verifications.length,
          returned: selected.length,
          truncated: (meta.total_count ?? verifications.length) > selected.length,
          pagination: meta,
          safety:
            "Presigned URLs expire in about 15 minutes. A human must inspect the document; the model must never request raw image bytes.",
          submissions: selected.map(verification =>
            kycSummary(verification, { includePreviewUrl: include_preview_urls }),
          ),
        });
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.registerTool(
    "get_admin_settings",
    {
      title: "Read platform gates and fee",
      description:
        "Returns the live enforce_verification_gate, enforce_payment_gate, and default_annual_fee_inr values plus the launch-threshold runbook. Read-only.",
      inputSchema: {},
      annotations: readOnly,
    },
    async () => {
      try {
        const payload = await apiRequest("/api/v1/admin/settings/gating");
        return ok({
          settings: payload?.data?.settings ?? null,
          runbook: {
            verification_gate:
              "Enable only when the target city has at least 50 active opposite-gender users and the account base is older than 7 days.",
            payment_gate:
              "Enable only when the target city has at least 250 active opposite-gender users.",
            default_annual_fee_inr: 500,
          },
        });
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.registerTool(
    "lookup_invoices",
    {
      title: "Search invoices",
      description:
        "Searches billing invoices by invoice number, member email, @handle, or shortid. Returns line-item amounts, status, period, and a safe member summary. Read-only.",
      inputSchema: {
        query: z
          .string()
          .min(1)
          .describe("Invoice number, member email, @handle, or shortid."),
        limit: z.coerce
          .number()
          .int()
          .min(1)
          .max(50)
          .default(20)
          .describe("Maximum invoices to return, capped at 50."),
      },
      annotations: readOnly,
    },
    async ({ query, limit }) => {
      try {
        const payload = await apiRequest("/api/v1/admin/invoices", {
          query: { query },
        });

        const invoices = Array.isArray(payload?.data?.invoices) ? payload.data.invoices : [];
        const selected = invoices.slice(0, limit);

        return ok({
          query,
          total_matched: invoices.length,
          returned: selected.length,
          note: GST_NOTE,
          invoices: selected.map((invoice) => ({
            id: invoice.id,
            invoice_number: invoice.invoice_number,
            item_type: invoice.item_type,
            description: invoice.description,
            base_amount_inr: invoice.base_amount_inr,
            gst_amount_inr: invoice.gst_amount_inr,
            total_amount_inr: invoice.total_amount_inr,
            status: invoice.status,
            period_start: invoice.period_start,
            period_end: invoice.period_end,
            payment_reference: invoice.payment_reference,
            pdf_url: invoice.pdf_url,
            issued_at: invoice.inserted_at,
            user: userSummary(invoice.user),
          })),
        });
      } catch (error) {
        return fail(error);
      }
    },
  );

  // -------------------------------------------------------------------------
  // Human-confirmed write tools
  // -------------------------------------------------------------------------

  server.registerTool(
    "review_kyc_submission",
    {
      title: "Approve or reject a KYC submission",
      description:
        "Approves or rejects one pending identity verification. With confirm: false it only previews the submission and the intended decision; with confirm: true it performs the action. A rejection reason is mandatory. A human must inspect the presigned preview before approving.",
      inputSchema: {
        verification_id: z.string().min(1).describe("Identity verification UUID."),
        decision: z.enum(["approve", "reject"]).describe("Final decision."),
        reason: z
          .string()
          .max(1_000)
          .optional()
          .describe("Mandatory for reject; ignored for approve."),
        confirm: z
          .boolean()
          .default(false)
          .describe("Must be true to mutate. False returns a preview only."),
      },
      annotations: confirmedWrite,
    },
    async ({ verification_id, decision, reason, confirm }) => {
      try {
        const trimmedReason = clean(reason);

        if (decision === "reject" && trimmedReason.length < 3) {
          return fail(
            new Error("A specific rejection reason of at least 3 characters is required."),
          );
        }

        if (!confirm) {
          const payload = await apiRequest(`/api/v1/admin/verifications/${verification_id}`);
          const verification = payload?.data?.verification;

          if (!verification) {
            return fail(new Error("Verification not found."));
          }

          return confirmationRequired({
            action: `kyc.${decision}`,
            verification: kycSummary(verification),
            proposed_decision: decision,
            proposed_reason: decision === "reject" ? trimmedReason : null,
            warning:
              verification.status !== "pending_admin_review"
                ? `This submission is already ${verification.status}. Re-check before confirming.`
                : null,
            checklist:
              "Confirm name/age/gender alignment, inspect the presigned preview as a human, and resolve any duplicate identity-hash warning.",
          });
        }

        if (decision === "approve") {
          const payload = await apiRequest(
            `/api/v1/admin/verifications/${verification_id}/approve`,
            { method: "POST", body: {} },
          );

          return ok({
            action: "kyc.approve",
            audit_source: "mcp",
            message: "Verification approved. The raw document was purged.",
            verification: payload?.data?.verification
              ? kycSummary(payload.data.verification, { includePreviewUrl: false })
              : null,
          });
        }

        const payload = await apiRequest(`/api/v1/admin/verifications/${verification_id}/reject`, {
          method: "POST",
          body: { reason: trimmedReason },
        });

        return ok({
          action: "kyc.reject",
          audit_source: "mcp",
          message: "Verification rejected. The raw document was purged.",
          reason: trimmedReason,
          verification: payload?.data?.verification
            ? kycSummary(payload.data.verification, { includePreviewUrl: false })
            : null,
        });
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.registerTool(
    "update_platform_gates",
    {
      title: "Update platform gates and annual fee",
      description:
        "Updates enforce_verification_gate, enforce_payment_gate, and/or default_annual_fee_inr. With confirm: false it returns the current vs proposed values and the launch-threshold runbook; with confirm: true it applies the change.",
      inputSchema: {
        enforce_verification_gate: z
          .boolean()
          .optional()
          .describe("Verification enforcement master switch."),
        enforce_payment_gate: z
          .boolean()
          .optional()
          .describe("Annual-fee enforcement master switch."),
        default_annual_fee_inr: z.coerce
          .number()
          .int()
          .positive()
          .optional()
          .describe("Positive integer annual fee in INR."),
        confirm: z
          .boolean()
          .default(false)
          .describe("Must be true to mutate. False returns a preview only."),
      },
      annotations: confirmedWrite,
    },
    async ({
      enforce_verification_gate,
      enforce_payment_gate,
      default_annual_fee_inr,
      confirm,
    }) => {
      try {
        const changes = {};

        if (typeof enforce_verification_gate === "boolean") {
          changes.enforce_verification_gate = enforce_verification_gate;
        }
        if (typeof enforce_payment_gate === "boolean") {
          changes.enforce_payment_gate = enforce_payment_gate;
        }
        if (Number.isInteger(default_annual_fee_inr)) {
          changes.default_annual_fee_inr = default_annual_fee_inr;
        }

        if (Object.keys(changes).length === 0) {
          return fail(
            new Error(
              "Provide at least one of enforce_verification_gate, enforce_payment_gate, or default_annual_fee_inr.",
            ),
          );
        }

        const currentPayload = await apiRequest("/api/v1/admin/settings/gating");
        const current = currentPayload?.data?.settings ?? {};

        if (!confirm) {
          return confirmationRequired({
            action: "settings.gating.update",
            current_settings: current,
            proposed_changes: changes,
            runbook: {
              verification_gate:
                "Enable only when the city has at least 50 active opposite-gender users and the account base is older than 7 days.",
              payment_gate:
                "Enable only when the city has at least 250 active opposite-gender users.",
              default_fee_inr: 500,
            },
            warning:
              "Changing the fee does not modify already-issued invoices. Verify the target city thresholds with the human operator before confirming.",
          });
        }

        const payload = await apiRequest("/api/v1/admin/settings/gating", {
          method: "PATCH",
          body: { settings: changes },
        });

        return ok({
          action: "settings.gating.update",
          audit_source: "mcp",
          applied_changes: changes,
          settings: payload?.data?.settings ?? null,
        });
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.registerTool(
    "broadcast_system_notification",
    {
      title: "Broadcast a system notification",
      description:
        "Queues an in-app system notification for all members, a location segment, or specific identifiers. With confirm: false it returns the exact estimated recipient count without enqueueing; with confirm: true it enqueues the Oban broadcast.",
      inputSchema: {
        target_type: z.enum(["all", "location", "individual"]).describe("Audience selector."),
        title: z.string().min(1).max(200).describe("Notification title."),
        body: z.string().min(1).max(5_000).describe("Notification body."),
        state: z.string().optional().describe("State filter for target_type=location."),
        city: z.string().optional().describe("City filter for target_type=location."),
        gender: z
          .enum(["All", "Male", "Female"])
          .default("All")
          .describe("Optional gender filter."),
        identifiers: z
          .array(z.string().min(1))
          .default([])
          .describe("Emails or @handles for target_type=individual."),
        confirm: z
          .boolean()
          .default(false)
          .describe("Must be true to enqueue. False returns the recipient count only."),
      },
      annotations: confirmedWrite,
    },
    async ({ target_type, title, body, state, city, gender, identifiers, confirm }) => {
      try {
        if (target_type === "location" && !clean(state) && !clean(city)) {
          return fail(new Error("target_type=location requires state and/or city."));
        }

        if (target_type === "individual" && identifiers.length === 0) {
          return fail(new Error("target_type=individual requires at least one email or @handle."));
        }

        const payload = {
          target_type,
          title,
          body,
          state: state || null,
          city: city || null,
          gender,
          identifiers,
        };

        if (!confirm) {
          const preview = await apiRequest("/api/v1/admin/notifications/broadcast", {
            method: "POST",
            body: { ...payload, dry_run: true },
          });

          return confirmationRequired({
            action: "notifications.broadcast",
            audience: {
              target_type,
              state: state || null,
              city: city || null,
              gender,
              identifiers,
            },
            estimated_recipients: preview?.estimated_recipients ?? 0,
            preview: {
              title,
              body,
            },
            warning:
              preview?.estimated_recipients === 0
                ? "No members matched this audience. Do not confirm a zero-recipient broadcast."
                : null,
          });
        }

        const result = await apiRequest("/api/v1/admin/notifications/broadcast", {
          method: "POST",
          body: payload,
        });

        return ok({
          action: "notifications.broadcast",
          audit_source: "mcp",
          status: result?.status ?? "queued",
          estimated_recipients: result?.estimated_recipients ?? null,
          message: "The notification broadcast was enqueued through Oban.",
        });
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.registerTool(
    "queue_bulk_email",
    {
      title: "Queue a bulk email broadcast",
      description:
        "Queues batched Resend email jobs for explicit addresses or a verified location/gender segment. With confirm: false it returns the exact recipient count without enqueueing; with confirm: true it enqueues batches of 25.",
      inputSchema: {
        mode: z.enum(["manual", "location"]).describe("Recipient resolution mode."),
        subject: z.string().min(1).max(200).describe("Email subject."),
        content: z.string().min(1).max(20_000).describe("HTML body of the email."),
        emails: z
          .array(z.string().min(1))
          .default([])
          .describe("Explicit addresses for mode=manual."),
        state: z.string().optional().describe("State filter for mode=location."),
        city: z.string().optional().describe("City filter for mode=location."),
        gender: z
          .enum(["All", "Male", "Female"])
          .default("All")
          .describe("Optional gender filter."),
        confirm: z
          .boolean()
          .default(false)
          .describe("Must be true to enqueue. False returns the recipient count only."),
      },
      annotations: confirmedWrite,
    },
    async ({ mode, subject, content, emails, state, city, gender, confirm }) => {
      try {
        if (mode === "manual" && emails.length === 0) {
          return fail(new Error("mode=manual requires at least one email address."));
        }

        if (mode === "location" && !clean(state) && !clean(city)) {
          return fail(new Error("mode=location requires state and/or city."));
        }

        const payload = {
          mode,
          subject,
          content,
          emails,
          state: state || null,
          city: city || null,
          gender,
        };

        if (!confirm) {
          const preview = await apiRequest("/api/v1/admin/emails/bulk-send", {
            method: "POST",
            body: { ...payload, dry_run: true },
          });

          return confirmationRequired({
            action: "emails.bulk_send",
            mode,
            audience: {
              state: state || null,
              city: city || null,
              gender,
              emails,
            },
            recipient_count: preview?.recipient_count ?? 0,
            sample_recipients: preview?.sample_recipients ?? [],
            preview: { subject },
            warning:
              preview?.recipient_count === 0
                ? "No verified recipients matched. Do not confirm an empty send."
                : null,
          });
        }

        const result = await apiRequest("/api/v1/admin/emails/bulk-send", {
          method: "POST",
          body: payload,
        });

        return ok({
          action: "emails.bulk_send",
          audit_source: "mcp",
          status: result?.status ?? "queued",
          queued_count: result?.queued_count ?? null,
          message: "Bulk email batches were enqueued through Oban.",
        });
      } catch (error) {
        return fail(error);
      }
    },
  );

  // -------------------------------------------------------------------------
  // Peer verification bootstrap
  // -------------------------------------------------------------------------

  server.registerTool(
    "grant_peer_verifier",
    {
      title: "Grant peer verifier status",
      description:
        "Grants the Peer Verified badge and vouch credits to one member (identifier) or seeds up to 25 eligible members in a city so a new launch city can bootstrap the vouch chain. With confirm: false it previews the exact targets; with confirm: true it applies the grant and audit-logs source=mcp.",
      inputSchema: {
        identifier: z
          .string()
          .optional()
          .describe("Email, @handle, shortid, or numeric user id for a single-member grant or credit top-up."),
        state: z
          .string()
          .optional()
          .describe("Indian state name for city seed mode. Required with city."),
        city: z
          .string()
          .optional()
          .describe("City name for city seed mode. Required with state."),
        limit: z
          .number()
          .int()
          .min(1)
          .max(25)
          .default(10)
          .describe("Number of seed verifiers to grant in city mode."),
        credits: z
          .number()
          .int()
          .min(1)
          .max(20)
          .default(5)
          .describe("Vouch credits to assign. Defaults to 5."),
        confirm: z
          .boolean()
          .default(false)
          .describe("Must be true to mutate. False returns a preview only."),
      },
      annotations: confirmedWrite,
    },
    async ({ identifier, state, city, limit, credits, confirm }) => {
      try {
        const target = clean(identifier);
        const trimmedState = clean(state);
        const trimmedCity = clean(city);

        if (target && (trimmedState || trimmedCity)) {
          return fail(
            new Error(
              "Use either identifier (one member) or state + city (city seed), not both.",
            ),
          );
        }

        if (!target && (!trimmedState || !trimmedCity)) {
          return fail(
            new Error(
              "Provide identifier for one member, or both state and city for a city seed.",
            ),
          );
        }

        const mode = target ? "individual" : "city";
        const requestBody = target
          ? { identifier: target, credits, dry_run: !confirm }
          : {
              state: trimmedState,
              city: trimmedCity,
              limit,
              credits,
              dry_run: !confirm,
            };

        const payload = await apiRequest("/api/v1/admin/users/grant-peer-verifier", {
          method: "POST",
          body: requestBody,
        });

        if (!confirm) {
          const targets = Array.isArray(payload?.targets) ? payload.targets : [];
          const targetCount = payload?.target_count ?? targets.length;
          const creditsToSet = payload?.credits_to_set ?? credits;

          return confirmationRequired({
            action: "peer_verifier.grant",
            mode,
            scope: target
              ? { identifier: target }
              : { state: trimmedState, city: trimmedCity, limit },
            target_count: targetCount,
            credits_to_set: creditsToSet,
            targets: targets.map((user) => userSummary(user)),
            message:
              targetCount === 0
                ? "No eligible members matched. Nothing would be changed."
                : `${targetCount} member(s) would receive the Peer Verified badge with ${creditsToSet} vouch credit(s) each.`,
            warning:
              targetCount === 0
                ? "Adjust the identifier, city, or filters before confirming."
                : "Confirm only after reviewing the exact names above. Peer verification grants real vouching power.",
          });
        }

        const users = Array.isArray(payload?.users) ? payload.users : [];
        const grantedCount = payload?.target_count ?? users.length;
        const creditsToSet = payload?.credits_to_set ?? credits;

        return ok({
          action: "peer_verifier.grant",
          audit_source: "mcp",
          mode,
          target_count: grantedCount,
          credits_to_set: creditsToSet,
          message: `${grantedCount} member(s) now have the Peer Verified badge and ${creditsToSet} vouch credit(s).`,
          users: users.map((user) => userSummary(user)),
        });
      } catch (error) {
        return fail(error);
      }
    },
  );

  // -------------------------------------------------------------------------
  // Seed verifier review tools
  // -------------------------------------------------------------------------

  server.registerTool(
    "list_seed_verifier_candidates",
    {
      title: "List city seed verifier candidates",
      description:
        "Lists city seed-verifier candidates filtered by state, city, and status (default opted_in). Shows each member's email and the city's current approved count out of 10 so the operator can match emailed ID documents. Read-only.",
      inputSchema: {
        state: z
          .string()
          .optional()
          .describe("Indian state name, case-insensitive."),
        city: z.string().optional().describe("City name, case-insensitive."),
        status: z
          .enum(["opted_in", "invited", "approved", "opted_out"])
          .default("opted_in")
          .describe("Seed-verifier status to list."),
      },
      annotations: readOnly,
    },
    async ({ state, city, status }) => {
      try {
        const payload = await apiRequest("/api/v1/admin/seed-verifiers", {
          query: { state, city, status },
        });

        const users = Array.isArray(payload?.data?.users) ? payload.data.users : [];
        const target = payload?.data?.target ?? 10;

        return ok({
          filters: {
            state: state || null,
            city: city || null,
            status,
          },
          target,
          candidate_count: users.length,
          pii_policy:
            "Emails are shown so the operator can match emailed ID documents. Phone numbers stay masked.",
          candidates: users.map(user => ({
            ...seedCandidateSummary(user),
            approved_in_city: user.approved_in_city ?? 0,
            target: user.target ?? target,
            slots_remaining: Math.max(0, target - (user.approved_in_city ?? 0)),
          })),
        });
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.registerTool(
    "approve_seed_verifier",
    {
      title: "Approve a seed verifier",
      description:
        "Approves one opted-in city seed candidate after a human reviews their emailed government ID. With confirm: false it previews the candidate, the city's X/10 approved count, and the exact changes. With confirm: true the member becomes a Peer Verified seed verifier with vouch credits, and the action is audit-logged with source=mcp.",
      inputSchema: {
        identifier: z
          .string()
          .min(1)
          .describe("Email, @handle, shortid, or numeric id of the candidate whose ID was verified."),
        credits: z
          .number()
          .int()
          .min(1)
          .max(20)
          .default(5)
          .describe("Initial vouch credits to grant. Defaults to 5."),
        notes: z
          .string()
          .max(1_000)
          .optional()
          .describe('Optional audit note, for example "Verified Driving License via email".'),
        confirm: z
          .boolean()
          .default(false)
          .describe("Must be true to approve. False returns a preview only."),
      },
      annotations: confirmedWrite,
    },
    async ({ identifier, credits, notes, confirm }) => {
      try {
        const trimmedNotes = clean(notes);

        const payload = await apiRequest("/api/v1/admin/seed-verifiers/approve", {
          method: "POST",
          body: {
            identifier,
            credits,
            notes: trimmedNotes || null,
            dry_run: !confirm,
            // The human confirmation is `confirm: true`. The override flag lets
            // the preview explain why an invited/none candidate is eligible.
            allow_override: true,
          },
        });

        if (!confirm) {
          const data = payload?.data ?? {};
          const candidate = seedCandidateSummary(data.user);
          const approved = data.approved_in_city ?? candidate?.approved_in_city ?? 0;
          const target = data.target ?? 10;

          return confirmationRequired({
            action: "seed_verifier.approve",
            candidate,
            city: candidate?.city ?? null,
            state: candidate?.state ?? null,
            city_progress: `${approved} / ${target}`,
            proposed_changes: data.changes ?? {},
            notes: trimmedNotes || null,
            message: candidate
              ? `Approving ${candidate.name ?? candidate.handle ?? candidate.email} will make them a Peer Verified seed verifier in ${candidate.city ?? "their city"} (${approved}/${target} approved there).`
              : "Review the seed candidate before confirming.",
            warning:
              data.warning ??
              (approved >= target
                ? "This city already has ten approved seed verifiers. Confirm only if this candidate is genuinely needed."
                : null),
          });
        }

        const data = payload?.data ?? {};
        const candidate = seedCandidateSummary(data.user);
        const thresholdReached = Boolean(data.threshold_reached);

        return ok({
          action: "seed_verifier.approve",
          audit_source: "mcp",
          message: candidate
            ? `${candidate.name ?? candidate.email} is now a Peer Verified seed verifier with ${candidate.vouch_credits_remaining} vouch credit(s).`
            : "Seed verifier approved.",
          city_progress: `${data.approved_in_city ?? 0} / ${data.target ?? 10}`,
          city_message: payload?.message ?? null,
          threshold_reached: thresholdReached,
          candidate,
          approved_in_city: data.approved_in_city ?? null,
          target: data.target ?? 10,
          note: trimmedNotes || null,
        });
      } catch (error) {
        return fail(error);
      }
    },
  );

  // -------------------------------------------------------------------------
  // Safety report moderation tools
  // -------------------------------------------------------------------------

  server.registerTool(
    "list_user_reports",
    {
      title: "List user safety reports",
      description:
        "Lists member reports filtered by status (default pending). Shows the reported member, reporter, reason, details, and total reports against the member. Read-only.",
      inputSchema: {
        status: z
          .enum(["pending", "reviewed_action_taken", "dismissed"])
          .default("pending")
          .describe("Report status to list."),
        limit: z
          .number()
          .int()
          .min(1)
          .max(100)
          .default(25)
          .describe("Maximum reports to return, capped at 100."),
      },
      annotations: readOnly,
    },
    async ({ status, limit }) => {
      try {
        const payload = await apiRequest("/api/v1/admin/reports", {
          query: { status },
        });

        const reports = Array.isArray(payload?.data?.reports) ? payload.data.reports : [];
        const selected = reports.slice(0, limit);

        return ok({
          status_filter: status,
          total_matched: reports.length,
          returned: selected.length,
          truncated: reports.length > selected.length,
          pii_policy:
            "Emails are shown for moderation context. Admin notes are included for reviewed reports.",
          reports: selected.map(report => ({
            id: report.id,
            reason: report.reason,
            details: report.details ?? null,
            status: report.status,
            admin_notes: report.admin_notes ?? null,
            submitted_at: report.inserted_at ?? null,
            reviewed_at: report.reviewed_at ?? null,
            reported_user: {
              id: report.reported_user?.id ?? null,
              name: fullName(report.reported_user),
              email: report.reported_user?.email ?? null,
              handle: report.reported_user?.user_handle
                ? `@${report.reported_user.user_handle}`
                : null,
              city: report.reported_user?.city ?? null,
              state: report.reported_user?.state ?? null,
              user_state: report.reported_user?.user_state ?? null,
              total_reports: report.reported_user_report_count ?? 0,
            },
            reporter: {
              id: report.reporter?.id ?? null,
              name: fullName(report.reporter),
              email: report.reporter?.email ?? null,
              handle: report.reporter?.user_handle
                ? `@${report.reporter.user_handle}`
                : null,
            },
          })),
        });
      } catch (error) {
        return fail(error);
      }
    },
  );

  server.registerTool(
    "resolve_user_report",
    {
      title: "Resolve or dismiss a user report",
      description:
        "Resolves a pending member safety report. With confirm: false it previews the report and the proposed decision; with confirm: true it marks the report dismissed or action-taken, optionally suspends the reported member, and audit-logs source=mcp.",
      inputSchema: {
        report_id: z.string().min(1).describe("User report id."),
        decision: z
          .enum(["dismiss", "reviewed_action_taken"])
          .describe("Dismiss the report or mark action taken."),
        suspend_user: z
          .boolean()
          .default(false)
          .describe("Deactivate the reported member. Only valid with reviewed_action_taken."),
        admin_notes: z
          .string()
          .max(2_000)
          .optional()
          .describe("Optional moderation note stored on the report and audit log."),
        confirm: z
          .boolean()
          .default(false)
          .describe("Must be true to resolve. False returns a preview only."),
      },
      annotations: confirmedWrite,
    },
    async ({ report_id, decision, suspend_user, admin_notes, confirm }) => {
      try {
        if (decision === "dismiss" && suspend_user) {
          return fail(new Error("suspend_user can only be used with reviewed_action_taken."));
        }

        const trimmedNotes = clean(admin_notes);
        const nextStatus = decision === "dismiss" ? "dismissed" : "reviewed_action_taken";

        if (!confirm) {
          const payload = await apiRequest(
            `/api/v1/admin/reports/${encodeURIComponent(report_id)}`,
          );
          const report = payload?.data?.report;

          if (!report) return fail(new Error("Report not found."));

          return confirmationRequired({
            action: `user_report.${decision}`,
            report: {
              id: report.id,
              reason: report.reason,
              details: report.details ?? null,
              status: report.status,
              submitted_at: report.inserted_at ?? null,
              reported_user: {
                id: report.reported_user?.id ?? null,
                name: fullName(report.reported_user),
                email: report.reported_user?.email ?? null,
                handle: report.reported_user?.user_handle
                  ? `@${report.reported_user.user_handle}`
                  : null,
                city: report.reported_user?.city ?? null,
                state: report.reported_user?.state ?? null,
                total_reports: report.reported_user_report_count ?? 0,
              },
              reporter: {
                id: report.reporter?.id ?? null,
                name: fullName(report.reporter),
                email: report.reporter?.email ?? null,
              },
            },
            proposed_status: nextStatus,
            suspend_user,
            admin_notes: trimmedNotes || null,
            warning:
              report.status !== "pending"
                ? `This report is already ${report.status}.`
                : suspend_user
                  ? "Confirming will deactivate the reported member."
                  : null,
          });
        }

        const payload = await apiRequest(
          `/api/v1/admin/reports/${encodeURIComponent(report_id)}`,
          {
            method: "PATCH",
            body: {
              status: nextStatus,
              suspend_user,
              admin_notes: trimmedNotes || null,
            },
          },
        );

        const report = payload?.data?.report;

        return ok({
          action: `user_report.${decision}`,
          audit_source: "mcp",
          message:
            decision === "dismiss"
              ? "Report dismissed."
              : suspend_user
                ? "Report resolved and the member was suspended."
                : "Report resolved.",
          status: report?.status ?? nextStatus,
          suspend_user,
          admin_notes: trimmedNotes || null,
          reported_user: report?.reported_user
            ? {
                id: report.reported_user.id,
                name: fullName(report.reported_user),
                email: report.reported_user.email ?? null,
                user_state: report.reported_user.user_state ?? null,
                total_reports: report.reported_user_report_count ?? 0,
              }
            : null,
        });
      } catch (error) {
        return fail(error);
      }
    },
  );

  // -------------------------------------------------------------------------
  // Prompts and runbook resources
  // -------------------------------------------------------------------------

  server.registerPrompt(
    "kyc_review_checklist",
    {
      title: "KYC review checklist",
      description:
        "Operational checklist for reviewing a MarryLocal identity verification, including human preview inspection and duplicate warnings.",
      argsSchema: {
        verification_id: z
          .string()
          .optional()
          .describe("Optional verification UUID to focus the checklist."),
      },
    },
    ({ verification_id }) => ({
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: verification_id
              ? `${KYC_REVIEW_CHECKLIST}\n\nFocus submission: \`${verification_id}\`.\nStart with \`review_kyc_submission\` and \`confirm: false\`.`
              : KYC_REVIEW_CHECKLIST,
          },
        },
      ],
    }),
  );

  server.registerPrompt(
    "gate_toggle_runbook",
    {
      title: "Gate toggle runbook",
      description:
        "MarryLocal launch thresholds and the safe procedure for enabling verification and annual-fee gates.",
      argsSchema: {
        city: z.string().optional().describe("Optional city to mention in the runbook."),
      },
    },
    ({ city }) => ({
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: city
              ? `${GATE_TOGGLE_RUNBOOK}\n\nTarget city for this review: ${city}. Verify the thresholds for this specific city.`
              : GATE_TOGGLE_RUNBOOK,
          },
        },
      ],
    }),
  );

  server.registerResource(
    "kyc_review_checklist",
    "marrylocal://runbooks/kyc-review-checklist",
    {
      title: "MarryLocal KYC review checklist",
      description:
        "Name/age/gender alignment, duplicate identity-hash warnings, presigned preview handling, and rejection guidance.",
      mimeType: "text/markdown",
    },
    async (uri) => ({
      contents: [
        {
          uri: uri.href,
          mimeType: "text/markdown",
          text: KYC_REVIEW_CHECKLIST,
        },
      ],
    }),
  );

  server.registerResource(
    "gate_toggle_runbook",
    "marrylocal://runbooks/gate-toggle-runbook",
    {
      title: "MarryLocal gate toggle runbook",
      description:
        "Launch thresholds for verification and payment gates plus the safe confirmation and rollback procedure.",
      mimeType: "text/markdown",
    },
    async (uri) => ({
      contents: [
        {
          uri: uri.href,
          mimeType: "text/markdown",
          text: GATE_TOGGLE_RUNBOOK,
        },
      ],
    }),
  );

  return server;
}

async function main() {
  if (!process.env.MARRYLOCAL_API_URL) {
    console.error(
      "[marrylocal-mcp] MARRYLOCAL_API_URL is not set. Defaulting to http://localhost:4000.",
    );
  }

  if (!CONFIGURED_TOKEN && (!ADMIN_EMAIL || !ADMIN_PASSWORD)) {
    console.error(
      "[marrylocal-mcp] No admin credential configured. Set MARRYLOCAL_ADMIN_TOKEN, or both MARRYLOCAL_ADMIN_EMAIL and MARRYLOCAL_ADMIN_PASSWORD.",
    );
  }

  const server = buildServer();
  const transport = new StdioServerTransport();

  await server.connect(transport);
  console.error(`[marrylocal-mcp] Connected over stdio. Backend: ${API_URL}`);

  const shutdown = async (signal) => {
    console.error(`[marrylocal-mcp] Received ${signal}; shutting down.`);
    try {
      await server.close();
    } finally {
      process.exit(0);
    }
  };

  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
}

main().catch((error) => {
  console.error(`[marrylocal-mcp] Fatal startup error: ${error?.stack || error}`);
  process.exit(1);
});
