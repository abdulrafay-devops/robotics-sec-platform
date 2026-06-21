# Interview Preparation Guide — Robotics Security Platform

A four-part PDF set that explains the entire project end to end, in plain language
with examples, analogies, and ASCII diagrams. If you read only these, you can
explain and demo the whole platform confidently.

## The four PDFs (read in this order)

1. **Part1-Foundations-and-Architecture.pdf** — the problem (OT/IT convergence),
   the vocabulary you must own, the six zones, network segmentation, the two data
   flows, and the tech stack.
2. **Part2-Plant-Floor-OT-and-Safety.pdf** — the PLC and its code, the robot,
   Modbus and its attacks, SROS2 certificate security, and the independent safety
   system (heartbeat, watchdog, latched E-stop).
3. **Part3-Detection-AI-Response-DevSecOps.pdf** — network monitoring, the 20
   features, the three ML models, incident response (graded containment),
   vulnerability management, the six-gate CI/CD pipeline, monitoring, and the dashboard.
4. **Part4-Demo-QA-and-Cheat-Sheets.pdf** — how to run it, the live demo script
   (what to click and what to say), the CI/CD gate demo, likely questions with
   answers, honest production trade-offs, standards mapping, and one-page cheat-sheets.

**Suggested study path:** read Part 1 first (the mental model), then Part 4 (the
words and the demo), then Parts 2 and 3 for the deep technical detail.

## Accuracy

Every fact in these PDFs is drawn from the actual code and configuration in this
repository (the `vm-ot`, `vm-sec`, `vm-ai`, `dashboard`, `infra`, and `demos`
trees) and from the existing project docs (`ARCHITECTURE-DIAGRAMS.md`,
`INTERVIEW-ARCHITECTURE-WALKTHROUGH.md`, `AUDIT-REPORT.md`, `FIXES-APPLIED.md`,
`INTERVIEW-DEMO-GUIDE.md`). Where the system has known limitations, the guide states
them honestly as "what I would harden for production."

## Regenerating the PDFs

```bash
pip install reportlab
cd interview-prep
python build_part1.py
python build_part2.py
python build_part3.py
python build_part4.py
```

`_pdfkit.py` holds the shared styling; each `build_partN.py` holds that part's content.
