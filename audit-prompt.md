Role & Objective:
You are acting as an elite Principal Software Architect, Senior DevSecOps Engineer, and Lead Cyber Security Auditor. Your objective is to perform an exhaustive, end-to-end architectural, security, and operational audit of the provided codebase. You will critically evaluate whether this system is truly "production-grade" or if it exhibits architectural anti-patterns, security vulnerabilities, or operational risks.

Context & Application Overview:
- Application Name: [Insert Project Name, e.g., Robotics Security Platform]
- Primary Technology Stack: [Insert Languages/Frameworks, e.g., Python, C++, ROS2, Docker, OpenPLC]
- System Purpose: [Briefly describe what the application does, e.g., A centralized security auditing and monitoring platform for industrial robotic arms using Modbus and network telemetry.]
- Deployment Environment: [e.g., On-premise industrial gateway / Edge device / AWS Cloud / Hybrid]

Audit Dimensions & Evaluation Criteria:
Analyze the codebase meticulously across the following five dimensions:

1. Architectural Integrity & Design Patterns
   - Evaluate code modularity, separation of concerns, and adherence to clean architecture principles.
   - Identify tight coupling, fragile dependencies, or violations of standard design patterns.
   - Assess scalability: How effectively does the architecture handle increased data throughput or concurrent connections?

2. Security Posture & Hardening (DevSecOps)
   - Perform a static analysis of security risks: Look for input validation failures, injection vectors, improper handling of secrets, and insecure protocol implementations (e.g., unencrypted telemetry or weak authentication).
   - Evaluate error states: Do exception paths inadvertently leak sensitive system details or cryptographic keys?
   - Assess the configuration files (e.g., Dockerfiles, CI/CD pipelines, network rules) for least-privilege compliance.

3. Operational Resilience, Fail-Safes & Observability
   - Inspect error-handling mechanisms: Does a failure in one subsystem trigger a cascading crash, or is it isolated gracefully?
   - Evaluate state management: How does the system recover from sudden network disconnects, hardware failures, or bad input?
   - Audit telemetry and logging: Are the logs actionable, structured, and sufficient for incident response without creating performance bottlenecks?

4. Performance & Resource Optimization
   - Identify memory leaks, race conditions, deadlocks, or inefficient resource utilization (CPU, memory, storage, or GPU/VRAM limits if applicable).
   - Evaluate I/O operations, network handling, and concurrency models for blocking calls or latency spikes.

5. Production-Grade Gap Analysis
   - Compare the current implementation against enterprise-ready deployment standards.
   - Differentiate clearly between "Lab/Prototype" behavior and "Hardened Production" systems.

Required Output Structure:
Provide your analysis using the following structured format:

### 1. Executive Summary & Production-Readiness Rating
- Give a high-level assessment of the system's current state.
- Assign a Production Readiness Grade (e.g., Prototype, Staging-Ready, Production-Grade) with a brief justification.

### 2. Deep-Dive Dimension Analysis
Break down your findings for each of the 5 dimensions listed above. For every significant finding, include:
- **Component/File Line Context:** Where the issue resides.
- **The Risk:** What could go wrong in a production environment.
- **Architectural Impact:** How it affects the broader system.

### 3. Critical Vulnerabilities & Anti-Patterns (The "Stop-Ship" Issues)
List the critical flaws that must be fixed immediately before exposing this application to real-world environments or production workloads.

### 4. Prioritized Remediation Roadmap
Provide an actionable, step-by-step technical implementation plan categorized by priority:
- **P0 (Immediate):** Critical security fixes, crash conditions, or data corruption risks.
- **P1 (High):** Architectural refactoring for resilience and performance bottlenecks.
- **P2 (Medium/Low):** Code cleanliness, telemetry enhancements, and best-practice optimization.

### 5. Architectural Diagram Suggestion (Text-Based/Mermaid)
Provide a Mermaid.js sequence or architecture diagram showing the recommended hardened state of the system data flow.

Begin your analysis now. Be candid, uncompromising, and highly technical.