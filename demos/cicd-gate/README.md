# CI/CD Gate Demo — prove the security gate catches unsafe PLC code on a git push

**The story you tell:** *PLC ladder logic is code, and unsafe code on a robot is a hazard.
Every push runs a deterministic gate; here's a commit it rejects, and the same feature
written safely that it accepts.* That's **DevSecOps for industrial automation** (Topic 114),
demonstrated live.

How it works: you push to Gitea → Gitea fires a **webhook** into the AI plane → the
**same** `run_pipeline.sh` gate engine runs the code-quality gates (PLC / HMI / SROS2
lints) → the **PASS / FAIL verdict shows on your dashboard**.

```
  git push  ─►  Gitea (IT zone)  ──webhook──►  AI container runs the gates  ──►  PASS / FAIL on your dashboard
```

> All URLs are for the host (`localhost`). Run git commands from the project root:
> `D:\Robotics Security platform\Robotics platform-antigravity\robotics-app-idmz`.

---

## 0. Why the webhook — and not the Gitea Actions runner

Gitea Actions (the ✔/✘ checks in the **Actions** tab) needs a **runner** — a separate
worker that executes the job. Making that work *in this IDMZ lab* means standing up a lot
of fragile plumbing for a single-laptop demo:

- registering a runner and keeping its token valid,
- giving it the **Docker socket** so it can spawn job containers,
- wiring the **job container's network** so it can reach Gitea *across IDMZ zones* to check
  out the code, and
- a **~1.5 GB** runner image download — none of which survives a `docker compose up`
  without a custom runner image.

So if you push with Actions enabled, the run just **sits "pending" forever** (no runner) —
that red ❌ / ⏳ in the Actions tab is *"no worker showed up,"* **not** your gate catching a
bug. Don't demo that screen.

The **webhook** triggers the **identical** `run_pipeline.sh` engine directly in the AI
container — no runner, no Docker-in-Docker, no cross-zone job networking — and the result
lands on **your own SOC dashboard**, which is a stronger story than a generic green check.

> Honest one-liner if asked: *"The workflow file (`.gitea/workflows/ci.yml`) defines the same
> gates; in production a registered Actions runner executes them. For a single-laptop lab I
> trigger the same engine via a push webhook into the AI plane — identical gate logic, no
> dedicated runner VM."*

---

## 1. One-time setup (~5 min, do this before the interview)

**a. Account + repo (only you can do this):**
1. `http://localhost:3000` → **Register** → pick a username/password.
2. **+ → New Repository** → name `robotics-platform` → leave empty → **Create**.

**b. Push the code:**
```bash
git remote add gitea http://localhost:3000/<YOUR_USER>/robotics-platform.git
git push -u gitea main      # prompts for your Gitea username + password
```
> `.env` is git-ignored, so your secrets are **not** pushed. Good.

**c. Add the webhook** — repo → **Settings → Webhooks → Add Webhook → Gitea**:
| Field | Value |
|---|---|
| **Target URL** | `http://192.168.40.30:9000/webhook` |
| **HTTP Method** | `POST` |
| **Content Type** | `application/json` |
| **Secret** | the **value only** of `GITEA_WEBHOOK_SECRET` from your `.env` |
| **Trigger** | **Push events** |

→ click **Add Webhook**.

> ⚠️ **The #1 gotcha — the secret.** In `.env` the line is `GITEA_WEBHOOK_SECRET=2d76b9…`.
> Paste **only the part after the `=`** (the 64 hex characters) — **no leading `=`, no spaces,
> no quotes.** A wrong secret = Gitea delivers but the receiver returns **`403 signature
> mismatch`** and nothing runs (the dashboard keeps showing a stale verdict).
>
> **Verify it now:** in the webhook page → **Recent Deliveries → Test Delivery**. You want a
> green ✓ / response **`200`**. A red **`403`** means the secret has an extra character — fix
> and retest.

**d. (Recommended) hide the dead Actions tab:** repo → **Settings → Units** → untick
**Actions** → Update. Now there's no confusing "pending" run; only the webhook path remains.

---

## 2. The interview demo — step by step (RED, then GREEN)

The webhook lints your **working tree** (the project folder), so each step **copies a file
in, commits, and pushes** — the push is the trigger.

**Watch one of these while you push** (keep it open on screen):
- Dashboard → **Stages** → *Pipeline Verdict*, **or**
- Grafana `http://localhost:3003/d/lab-vuln` → **"CI/CD Gate Verdict — history"** timeline.

### Step 1 — show the baseline
"Here's the pipeline verdict for the current `main`: **green / PASS**." (Point at the dashboard.)

### Step 2 — introduce unsafe PLC code → goes RED
> "PLC ladder logic is code. Watch what happens when I push an unsafe manual-jog routine."
```bash
cp demos/cicd-gate/demo_jog.VULNERABLE.st vm-ot/openplc/demo_jog.st
git add vm-ot/openplc/demo_jog.st
git commit -m "Add manual jog routine"
git push gitea main
```
Within a few seconds the dashboard flips to **FAIL (red)**. Say what it caught:
> "The gate rejected it — **7 findings**: an unsigned program, a motion block with no
> emergency-stop guard, a hard-coded `admin` credential, writes to safety outputs from
> non-safety code, and an unbounded loop. That commit can't reach the plant."

*(Optional, to show the actual lint output on screen:)*
```bash
docker exec container-ai sh -c 'cat $(ls -td /var/lab/artifacts/*/ | head -1)pipeline.log' | grep -A2 plc_lint
```

### Step 3 — fix it the safe way → goes GREEN
> "Now the same feature, written safely — E-stop guarded, no credentials, bounded loop, signed."
```bash
cp demos/cicd-gate/demo_jog.CLEAN.st vm-ot/openplc/demo_jog.st
git add vm-ot/openplc/demo_jog.st
git commit -m "Harden jog routine: add E-stop guard, remove creds, bound loop, sign program"
git push gitea main
```
The dashboard flips to **PASS (green)**.

### Step 4 — clean up (so the repo stays green)
```bash
git rm vm-ot/openplc/demo_jog.st
git commit -m "remove demo"
git push gitea main
```

---

## 3. What the gate checks (the two demo files)

| File | Result | Why |
|------|--------|-----|
| `demo_jog.VULNERABLE.st` | **FAIL** (7 findings) | unsigned program (R6); motion with no E-stop guard (R2); hard-coded `'admin'` credential (R1); safety-output writes outside a `SAFETY_` block (R3 ×2); unbounded `FOR` loop (R4); commented-out safety check (R5) |
| `demo_jog.CLEAN.st` | **PASS** (0 findings) | signed; E-stop / `SAFETY_OK`-guarded motion; no creds; safety output only inside the `SAFETY_` block; statically-bounded loop |

**Shift-left — run the exact gate locally before you ever push** (great to mention):
```bash
python3 vm-ai/devsecops/plc_lint.py vm-ot/openplc/demo_jog.st   # exit 1 = fail, 0 = pass
```
or the full static-gate set through the same engine the webhook uses:
```bash
LAB_GATES=plc,hmi,sros2 LAB_SOURCE_DIR=. LAB_PIPELINE_PY=$(command -v python3) \
  LAB_LOG_DIR=/tmp/pipeline-log LAB_ARTIFACTS_DIR=/tmp/pipeline-artifacts \
  bash vm-ai/devsecops/run_pipeline.sh
```

---

## 4. If the verdict doesn't change when you push

| Symptom | Cause | Fix |
|---|---|---|
| Webhook **Test Delivery = 403** | secret has an extra char (the `=`) | re-paste the 64 hex chars only, Update, retest |
| Dashboard verdict never updates | webhook not saved, or wrong URL | confirm URL is `http://192.168.40.30:9000/webhook`; check **Recent Deliveries** |
| Actions tab shows red ❌ / pending ⏳ | that's the *runner* (no runner exists) | ignore it — or untick **Actions** in repo Units. It is **not** your gate result. |
| `git push` says "Everything up-to-date" | no new commit, so no webhook fired | make a change (or `git commit --allow-empty -m trigger`) and push |

**Talking point:** *"It's one gate engine, two triggers — the Actions workflow and the
in-lab webhook both execute the same `run_pipeline.sh`, so a check can't pass in CI yet fail
in the plant pipeline. The gate blocks unsigned programs, motion with no emergency-stop
guard, hard-coded credentials, writes to safety outputs from non-safety code, and unbounded
loops. Here's a commit it rejected, and here's the safe version it accepts."*
