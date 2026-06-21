# CI/CD Gate Demo — pushing code to Gitea & proving the security gates work

This shows three things end-to-end:
1. Get your code into Gitea and browse it.
2. Make the CI/CD pipeline run on every push (two ways — pick one).
3. Prove the gates work: push a **vulnerable** PLC program → build goes **red**; push the **clean** version → build goes **green**.

All URLs below are for the host (`localhost`). Logins are in `INTERVIEW-DEMO-GUIDE.md`.

---

## 1. Put your code in Gitea and see it

You've already registered a Gitea account at `http://localhost:3000`. Now create a repo and push:

1. In Gitea: **+ → New Repository** → name it `robotics-platform` (leave it empty — no README/.gitignore). Create.
2. On your machine, from the project root (`D:\…\robotics-app`):

   ```bash
   git add -A
   git commit -m "Initial import of robotics security platform"
   git remote add gitea http://localhost:3000/<YOUR_USER>/robotics-platform.git
   git branch -M main
   git push -u gitea main
   ```
   Gitea will prompt for your Gitea username + password.
3. Refresh the repo page in Gitea — you'll see the full tree (`vm-ot`, `vm-ai`, `vm-sec`, `dashboard`, …). Click any file to view it.

> `.env` is git-ignored, so your secrets are **not** pushed. Good.

---

## 2. Make CI run on every push — pick ONE path

### Path A (recommended for the demo): Gitea Actions runner — red/green checks in Gitea

This gives the classic ✔/✘ next to each commit and a full log in the **Actions** tab.

Actions and the `ubuntu-latest` runner label are already configured in `docker-compose.yml`, so setup is short:

1. **Uncomment the Docker socket line** on the `runner` service in `docker-compose.yml` (lab use only — it lets the runner start job containers):
   ```yaml
   - /var/run/docker.sock:/var/run/docker.sock
   ```
2. **Get a runner registration token:** Gitea → **Site Administration → Actions → Runners → Create new Runner** → copy the token. Put it in `.env`:
   ```
   GITEA_RUNNER_TOKEN=<paste token here>
   ```
3. **Enable Actions for the repo:** repo → **Settings → Advanced → Actions** → tick *Enable*.
4. Restart the two services:
   ```bash
   docker compose up -d gitea runner
   docker logs lab-gitea-runner   # should say "runner registered successfully"
   ```
5. The workflow is already in the repo at `.gitea/workflows/ci.yml`. Each gate step calls `vm-ai/devsecops/run_pipeline.sh` — the **same engine** the webhook path runs — selecting one gate via `LAB_GATES`, so CI and the lab pipeline can never drift apart. On your next push, open the repo's **Actions** tab to watch it run.

### Path B (simplest — no runner): webhook → the real Stage-5 pipeline

Gitea calls the pipeline service directly; the verdict shows on the dashboard **Stages** page.

1. Repo → **Settings → Webhooks → Add Webhook → Gitea**:
   - **Target URL:** `http://container-ai:9000/webhook`
   - **HTTP Method:** POST, **Content type:** `application/json`
   - **Secret:** the value of `GITEA_WEBHOOK_SECRET` from your `.env`
   - **Trigger:** Push events → Add Webhook.
2. Push any commit. The webhook fires `run_pipeline.sh` inside `container-ai` (all 6 gates).
3. See the result:
   - Dashboard → **Stages** page → *Pipeline Verdict* (PASS/FAIL), or
   - `docker logs container-ai | grep -A3 "Gate 1"` to see the lint output, or
   - `docker exec container-ai sh -c 'cat $(ls -td /var/lab/artifacts/*/ | head -1)verdict.json'`

> Note: the webhook pipeline lints the mounted working tree (`/vagrant` = your project folder), so make sure the file you're demoing is saved there before you push.

---

## 3. The gate demo — watch it catch a vulnerability

Two ready-made PLC programs live in this folder:

| File | Result | Why |
|------|--------|-----|
| `demo_jog.VULNERABLE.st` | **FAILS** (7 findings) | unsigned program (R6), motion block with no E-stop guard (R2), hard-coded `'admin'` credential (R1), safety-output writes outside a `SAFETY_` block (R3 ×2), unbounded `FOR` loop (R4), commented-out safety check (R5) |
| `demo_jog.CLEAN.st` | **PASSES** (0 findings) | signed, E-stop/`SAFETY_OK` guarded motion, no creds, safety output only inside the `SAFETY_` block, statically-bounded loop |

**Run it:**

```bash
# 1) Introduce the vulnerable program and push  -> build goes RED
cp demos/cicd-gate/demo_jog.VULNERABLE.st vm-ot/openplc/demo_jog.st
git add vm-ot/openplc/demo_jog.st
git commit -m "Add manual jog routine"
git push gitea main
#   Path A: repo -> Actions tab shows a red X on "Gate 1 - PLC Structured Text lint"
#   Path B: dashboard Stages page shows Pipeline Verdict = FAIL

# 2) Ship the hardened version and push       -> build goes GREEN
cp demos/cicd-gate/demo_jog.CLEAN.st vm-ot/openplc/demo_jog.st
git add vm-ot/openplc/demo_jog.st
git commit -m "Harden jog routine: add E-stop guard, remove creds, bound loop, sign program"
git push gitea main
#   Path A: green check.   Path B: Pipeline Verdict = PASS
```

**Try it locally first (no push needed)** — exactly what the gate runs:
```bash
python3 vm-ai/devsecops/plc_lint.py vm-ot/openplc/demo_jog.st   # exit 1 = fail, 0 = pass
```

or run the full static-gate set through the same engine CI uses (shift-left, before you push):
```bash
LAB_GATES=plc,hmi,sros2 LAB_SOURCE_DIR=. LAB_PIPELINE_PY=$(command -v python3) \
  LAB_LOG_DIR=/tmp/pipeline-log LAB_ARTIFACTS_DIR=/tmp/pipeline-artifacts \
  bash vm-ai/devsecops/run_pipeline.sh
```

**Talking point for the interview:** "PLC ladder logic is code, and unsafe code on a robot is a hazard. Every push runs a deterministic Structured-Text gate — it blocks unsigned programs, motion paths with no emergency-stop guard, hard-coded credentials, writes to safety outputs from non-safety code, and unbounded loops. Here's a commit it rejected, and here's the same feature written safely that it accepts. And it's one gate engine with two triggers — the Actions steps and the in-lab webhook both execute the same `run_pipeline.sh`, so a check can never pass in CI yet fail in the plant pipeline." That's *DevSecOps for industrial automation* (Topic 114) demonstrated live.

> Clean-up after the demo: `git rm vm-ot/openplc/demo_jog.st && git commit -m "remove demo" && git push gitea main` so the repo's own pipeline stays green.
