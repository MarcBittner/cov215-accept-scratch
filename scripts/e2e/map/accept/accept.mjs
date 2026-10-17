#!/usr/bin/env node
import { createHash } from "node:crypto"
import { appendFileSync, writeFileSync } from "node:fs"
import { fileURLToPath } from "node:url"

export const ACCEPT_LABEL = "accept-behaviour-change"
export const ROWS_SCHEMA_VERSION = "1.0"
export const ROWS_SECTION = "App map"
export const ACCEPT_GROUP_ID = "accept"

const SHA = /^[0-9a-f]{40}$/
const HASH = /^[0-9a-f]{64}$/
const WRITE_PERMISSIONS = new Set(["admin", "maintain", "write"])

export function reportedDiffHash(changes) {
  const lines = changes.map((c) => `${c.id}\u0000${c.digest}`).sort()
  for (let i = 1; i < lines.length; i++) {
    if (lines[i] === lines[i - 1]) throw new Error(`duplicate reported change ${lines[i].split("\u0000")[0]}`)
  }
  return createHash("sha256").update(lines.join("\n")).digest("hex")
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

function labelRefusal({ labelEvent, prAuthor, labelActorPermission }) {
  const actor = labelEvent.actor
  if (!actor || actor === prAuthor) return { reason: "author", actor }
  if (!hasWriteAccess(labelActorPermission)) return { reason: "no-write", actor }
  return null
}

export function evaluateAccept({ timeline, prAuthor, labelActorPermission, priorOutcome, headSha, diffHash }) {
  if (!SHA.test(headSha ?? "")) throw new Error(`bad head sha "${headSha}"`)
  if (!HASH.test(diffHash ?? "")) throw new Error(`bad diff hash "${diffHash}"`)
  if (typeof prAuthor !== "string" || prAuthor === "") throw new Error("prAuthor is required")
  const labelEvent = lastLabelEvent(timeline)
  if (!labelEvent) return { state: "absent", headSha }
  const refused = labelRefusal({ labelEvent, prAuthor, labelActorPermission })
  if (refused) return { state: "refused", ...refused, headSha, removeLabel: true }
  const actor = labelEvent.actor
  if (!priorOutcome) return { state: "refused", reason: "no-report", actor, headSha, removeLabel: true }
  const reportedAt = Date.parse(priorOutcome.reportedAt ?? "")
  if (!SHA.test(priorOutcome.head ?? "") || !HASH.test(priorOutcome.reportedDiffHash ?? "") || Number.isNaN(reportedAt)) {
    throw new Error("priorOutcome must carry head (full sha), reportedDiffHash (sha256) and reportedAt (ISO time)")
  }
  if (priorOutcome.reportedDiffHash !== diffHash) {
    return { state: "refused", reason: "diff-changed", actor, headSha, reportedHead: priorOutcome.head, previousDiffHash: priorOutcome.reportedDiffHash, diffHash, removeLabel: true }
  }
  const labelledAt = Date.parse(labelEvent.at ?? "")
  if (Number.isNaN(labelledAt) || labelledAt <= reportedAt) {
    return { state: "refused", reason: "label-before-report", actor, headSha, reportedAt: priorOutcome.reportedAt, removeLabel: true }
  }
  return { state: "accepted", actor, headSha, diffHash, reportedHead: priorOutcome.head }
}

export function nextOutcome({ priorOutcome, headSha, diffHash, now }) {
  if (!SHA.test(headSha ?? "")) throw new Error(`bad head sha "${headSha}"`)
  if (!HASH.test(diffHash ?? "")) throw new Error(`bad diff hash "${diffHash}"`)
  const carried = priorOutcome && priorOutcome.reportedDiffHash === diffHash && !Number.isNaN(Date.parse(priorOutcome.reportedAt ?? ""))
  return { head: headSha, reportedDiffHash: diffHash, reportedAt: carried ? priorOutcome.reportedAt : new Date(now).toISOString() }
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
  "diff-changed": () => "the reported changes differ from the ones it accepted. Add it again to accept the changes below.",
  "label-before-report": () => "it was added before the current changes were reported. Add it again to accept the changes below.",
}

export function refusalText(evaluation) {
  return `Removed ${ACCEPT_LABEL}: ${REASONS[evaluation.reason](evaluation)}`
}

export function advisoryComment(evaluation) {
  return escapeMarkdown(`${ACCEPT_LABEL} will not count: ${REASONS[evaluation.reason](evaluation)} The next report applies this rule; this comment changes nothing.`)
}

export function acceptGroup({ evaluation, changes }) {
  const ids = changes.map((c) => c.id)
  const rows = []
  if (evaluation.state === "refused" && evaluation.reason === "diff-changed") {
    rows.push({ text: `${ACCEPT_LABEL} was removed: ${REASONS["diff-changed"](evaluation)}`, level: "fail", ids: [] })
  } else if (evaluation.state === "accepted") {
    rows.push({ text: `Accepted by ${evaluation.actor} for head ${evaluation.headSha.slice(0, 7)}.`, level: "info", ids: [] })
  } else if (evaluation.state === "refused") {
    rows.push({ text: refusalText(evaluation), level: "fail", ids: [] })
  }
  if (changes.length === 0) {
    rows.push({ text: "No behaviour or screen change reported.", level: "info", ids: [] })
  } else {
    const accepted = evaluation.state === "accepted"
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
    async permission(login) {
      const path = `collaborators/${encodeURIComponent(login)}/permission`
      const res = await call("GET", path)
      if (res.status === 404) return { permission: "none", role_name: "none" }
      if (!res.ok) throw Object.assign(new Error(`GitHub ${res.status} for ${path}`), { status: res.status })
      return res.json()
    },
    async comment(n, body) {
      const res = await call("POST", `issues/${n}/comments`, { body })
      if (!res.ok) throw Object.assign(new Error(`GitHub ${res.status} for issues/${n}/comments`), { status: res.status })
    },
  }
}

export async function adviseLabel({ client, prNumber, eventSha = "", log = console.log }) {
  if (!/^[1-9][0-9]{0,9}$/.test(String(prNumber))) throw new Error(`bad pull request number "${prNumber}"`)
  const pr = await client.getPull(prNumber)
  if (eventSha && eventSha !== pr.head.sha) log(`event sha ${eventSha} is not the head; using head ${pr.head.sha}`)
  const labelEvent = lastLabelEvent(await client.timeline(prNumber))
  if (!labelEvent || !pr.labels.some((l) => l.name === ACCEPT_LABEL)) return { state: "absent", headSha: pr.head.sha, commented: false }
  const permission = labelEvent.actor ? await client.permission(labelEvent.actor) : null
  const refused = labelRefusal({ labelEvent, prAuthor: pr.user.login, labelActorPermission: permission })
  if (!refused) return { state: "pending-report", actor: labelEvent.actor, headSha: pr.head.sha, commented: false }
  const advice = { state: "will-not-count", ...refused, headSha: pr.head.sha }
  try {
    await client.comment(prNumber, advisoryComment(advice))
    advice.commented = true
  } catch (e) {
    if (e.status !== 403) throw e
    advice.commented = false
    log("token cannot write to this pull request (fork); the report applies the same rule")
  }
  return advice
}

function summaryLine(e) {
  if (e.state === "absent") return `\`${ACCEPT_LABEL}\` is not on the pull request (head ${e.headSha}).`
  if (e.state === "pending-report") return `\`${ACCEPT_LABEL}\` added by ${escapeMarkdown(e.actor)}; the next report decides whether it counts for head ${e.headSha}.`
  return `${advisoryComment(e)} (head ${e.headSha}, commented: ${e.commented})`
}

export async function main(argv = process.argv.slice(2), env = process.env) {
  const [command, out] = argv
  if (command !== "check") {
    console.error("usage: accept.mjs check [result.json]")
    return 2
  }
  const client = makeClient({ repo: env.GITHUB_REPOSITORY, token: env.GITHUB_TOKEN, apiUrl: env.GITHUB_API_URL })
  const evaluation = await adviseLabel({ client, prNumber: env.PR_NUMBER, eventSha: env.EVENT_SHA })
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
