#!/usr/bin/env node
import { createHash } from "node:crypto"
import { appendFileSync, writeFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

export const ACCEPT_LABEL = "accept-behaviour-change"
export const REPORT_BOT = "github-actions[bot]"
export const ROWS_SCHEMA_VERSION = "1.0"
export const ROWS_SECTION = "App map"
export const ACCEPT_GROUP_ID = "accept"

const SHA = /^[0-9a-f]{40}$/
const HASH = /^[0-9a-f]{64}$/
const MARKER = /<!-- e2e-accept-binding head=([0-9a-f]{40}) diff=([0-9a-f]{64}) -->/g
const WRITE_PERMISSIONS = new Set(["admin", "maintain", "write"])

export function reportedDiffHash(changes) {
  const lines = changes.map((c) => `${c.id}\u0000${c.digest}`).sort()
  for (let i = 1; i < lines.length; i++) {
    if (lines[i] === lines[i - 1]) throw new Error(`duplicate reported change ${lines[i].split("\u0000")[0]}`)
  }
  return createHash("sha256").update(lines.join("\n")).digest("hex")
}

export function bindingMarker({ headSha, diffHash }) {
  if (!SHA.test(headSha)) throw new Error(`bad head sha "${headSha}"`)
  if (!HASH.test(diffHash)) throw new Error(`bad diff hash "${diffHash}"`)
  return `<!-- e2e-accept-binding head=${headSha} diff=${diffHash} -->`
}

export function latestBinding(comments) {
  let best = null
  for (const c of comments) {
    if (c.user?.login !== REPORT_BOT || c.user?.type !== "Bot") continue
    const found = [...String(c.body ?? "").matchAll(MARKER)].at(-1)
    if (!found) continue
    const at = Date.parse(c.updated_at ?? c.created_at)
    if (best && at < best.at) continue
    best = { at, headSha: found[1], diffHash: found[2] }
  }
  return best && { headSha: best.headSha, diffHash: best.diffHash }
}

export function lastLabelEvent(timeline, label = ACCEPT_LABEL) {
  let last = null
  for (const e of timeline) {
    if ((e.event === "labeled" || e.event === "unlabeled") && e.label?.name === label) last = e
  }
  return last?.event === "labeled" ? { actor: last.actor?.login ?? null, at: last.created_at ?? null } : null
}

export function hasWriteAccess(permission) {
  return WRITE_PERMISSIONS.has(permission?.role_name) || WRITE_PERMISSIONS.has(permission?.permission)
}

export function evaluateLabel({ pr, labelEvent, permission, binding }) {
  const head = pr.head.sha
  if (!pr.labels.some((l) => l.name === ACCEPT_LABEL) || !labelEvent) return { state: "absent", headSha: head }
  const actor = labelEvent.actor
  if (!actor || actor === pr.user.login) return { state: "refused", reason: "author", actor, headSha: head }
  if (!hasWriteAccess(permission)) return { state: "refused", reason: "no-write", actor, headSha: head }
  if (!binding) return { state: "refused", reason: "no-report", actor, headSha: head }
  if (binding.headSha !== head) return { state: "refused", reason: "stale-report", actor, headSha: head, reportedHead: binding.headSha }
  return { state: "accepted", actor, headSha: head, diffHash: binding.diffHash }
}

export function rebind({ accepted, headSha, diffHash }) {
  if (!accepted) return { action: "none" }
  if (accepted.diffHash === diffHash) return { action: "keep", headSha, diffHash }
  return { action: "remove", headSha, diffHash, previousDiffHash: accepted.diffHash }
}

export function neutraliseMentions(text) {
  return text.replace(/@(?=[A-Za-z0-9])/g, "@​")
}

export function escapeMarkdown(text) {
  return neutraliseMentions(
    String(text)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/([\\`*_{}[\]()#+\-.!|~])/g, "\\$1")
      .replace(/\r?\n/g, " "),
  )
}

const REASONS = {
  author: (e) => `it was added by ${e.actor ?? "an unknown user"}, the author of this pull request. Another person with write access has to add it.`,
  "no-write": (e) => `${e.actor} does not have write access to this repository.`,
  "no-report": () => "no behaviour or screen change has been reported for this pull request yet, so there is nothing to accept.",
  "stale-report": (e) => `the reported changes are for ${e.reportedHead.slice(0, 7)}, not for the current head ${e.headSha.slice(0, 7)}. Add the label again once the new report is posted.`,
}

export function refusalText(evaluation) {
  return `Removed ${ACCEPT_LABEL}: ${REASONS[evaluation.reason](evaluation)}`
}

export function refusalComment(evaluation) {
  return `${escapeMarkdown(refusalText(evaluation))}\n\n<!-- e2e-accept-refusal -->`
}

export function acceptGroup({ evaluation, changes, decision = { action: "none" } }) {
  const ids = changes.map((c) => c.id)
  const rows = []
  if (decision.action === "remove") {
    rows.push({ text: `${ACCEPT_LABEL} was removed: the reported changes differ from the ones it accepted. Add it again to accept the changes below.`, level: "fail", ids: [] })
  } else if (evaluation.state === "accepted") {
    rows.push({ text: `Accepted by ${evaluation.actor} for head ${evaluation.headSha.slice(0, 7)}.`, level: "info", ids: [] })
  } else if (evaluation.state === "refused") {
    rows.push({ text: refusalText(evaluation), level: "fail", ids: [] })
  }
  if (changes.length === 0) {
    rows.push({ text: "No behaviour or screen change reported.", level: "info", ids: [] })
  } else {
    const accepted = evaluation.state === "accepted" && decision.action !== "remove"
    for (const c of changes) rows.push({ text: c.text, level: accepted ? "info" : "fail", ids: [c.id] })
    if (!accepted) {
      rows.push({ text: `Add the label ${ACCEPT_LABEL} (someone other than the author, with write access) to accept all of these.`, level: "warn", ids })
    }
  }
  return { id: ACCEPT_GROUP_ID, title: "Behaviour and screen changes", rows }
}

/** @param {{ setupRunId: string | number, groups: ReturnType<typeof acceptGroup>[], error?: string | null }} args */
export function commentRowsT3({ setupRunId, groups, error = null }) {
  return {
    schema_version: ROWS_SCHEMA_VERSION,
    task: "t3",
    setup_run_id: String(setupRunId),
    section: ROWS_SECTION,
    status: error ? "error" : "ok",
    detail: error,
    groups,
  }
}

export function makeClient({ repo, token, fetch: fetchImpl = globalThis.fetch, apiUrl = "https://api.github.com" }) {
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo ?? "")) throw new Error(`bad repo "${repo}"`)
  if (!token) throw new Error("GitHub token missing")
  const base = `${apiUrl}/repos/${repo}/`
  async function call(method, path, body) {
    const res = await fetchImpl(base + path, {
      method,
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${token}`,
        "X-GitHub-Api-Version": "2022-11-28",
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
    return res
  }
  async function json(path) {
    const res = await call("GET", path)
    if (!res.ok) throw Object.assign(new Error(`GitHub ${res.status} for ${path}`), { status: res.status })
    return res.json()
  }
  async function paged(path) {
    const out = []
    for (let page = 1; page <= 30; page++) {
      const items = await json(`${path}${path.includes("?") ? "&" : "?"}per_page=100&page=${page}`)
      out.push(...items)
      if (items.length < 100) break
    }
    return out
  }
  return {
    getPull: (n) => json(`pulls/${n}`),
    timeline: (n) => paged(`issues/${n}/timeline`),
    comments: (n) => paged(`issues/${n}/comments`),
    async permission(login) {
      const path = `collaborators/${encodeURIComponent(login)}/permission`
      const res = await call("GET", path)
      if (res.status === 404) return { permission: "none", role_name: "none" }
      if (!res.ok) throw Object.assign(new Error(`GitHub ${res.status} for ${path}`), { status: res.status })
      return res.json()
    },
    async removeLabel(n) {
      const path = `issues/${n}/labels/${encodeURIComponent(ACCEPT_LABEL)}`
      const res = await call("DELETE", path)
      if (!res.ok && res.status !== 404) throw Object.assign(new Error(`GitHub ${res.status} for ${path}`), { status: res.status })
    },
    async comment(n, body) {
      const res = await call("POST", `issues/${n}/comments`, { body })
      if (!res.ok) throw Object.assign(new Error(`GitHub ${res.status} for issues/${n}/comments`), { status: res.status })
    },
  }
}

export async function checkLabel({ client, prNumber, eventSha = "", log = console.log }) {
  if (!/^[1-9][0-9]{0,9}$/.test(String(prNumber))) throw new Error(`bad pull request number "${prNumber}"`)
  const pr = await client.getPull(prNumber)
  if (eventSha && eventSha !== pr.head.sha) log(`event sha ${eventSha} is not the head; using head ${pr.head.sha}`)
  const labelEvent = lastLabelEvent(await client.timeline(prNumber))
  const permission = labelEvent?.actor ? await client.permission(labelEvent.actor) : null
  const binding = latestBinding(await client.comments(prNumber))
  const evaluation = evaluateLabel({ pr, labelEvent, permission, binding })
  if (evaluation.state === "refused") {
    try {
      await client.removeLabel(prNumber)
      await client.comment(prNumber, refusalComment(evaluation))
      evaluation.removed = true
    } catch (e) {
      if (e.status !== 403) throw e
      evaluation.removed = false
      log("token cannot write to this pull request (fork); the report applies the same rule")
    }
  }
  return evaluation
}

function summaryLine(e) {
  if (e.state === "absent") return `\`${ACCEPT_LABEL}\` is not on the pull request (head ${e.headSha}).`
  if (e.state === "accepted") return `\`${ACCEPT_LABEL}\` added by ${escapeMarkdown(e.actor)} counts for head ${e.headSha}, diff ${e.diffHash}.`
  return `${escapeMarkdown(refusalText(e))} (head ${e.headSha}, removed: ${e.removed})`
}

export async function main(argv = process.argv.slice(2), env = process.env) {
  const [command, out] = argv
  if (command !== "check") {
    console.error("usage: accept.mjs check [result.json]")
    return 2
  }
  const client = makeClient({ repo: env.GITHUB_REPOSITORY, token: env.GITHUB_TOKEN, apiUrl: env.GITHUB_API_URL })
  const evaluation = await checkLabel({ client, prNumber: env.PR_NUMBER, eventSha: env.EVENT_SHA })
  console.log(JSON.stringify(evaluation))
  if (out) writeFileSync(out, JSON.stringify(evaluation, null, 2) + "\n")
  if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, summaryLine(evaluation) + "\n")
  return 0
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main()
    .then((code) => process.exit(code))
    .catch((error) => {
      console.error(`ERROR: ${error.message}`)
      process.exit(1)
    })
}
