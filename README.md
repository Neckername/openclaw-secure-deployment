# Secure OpenClaw Docker Deployment

This repository keeps OpenClaw out of the host environment. The baseline deployment uses the existing `ghcr.io/phioranex/openclaw-docker:latest` container image, but runs it through our own least-privilege Compose settings, loopback-only host port publishing, local bind-mounted state, and repeatable audit scripts.

## Security Model

- OpenClaw is not installed globally with npm or a host daemon.
- Gateway ports are published to `127.0.0.1` by default.
- The gateway and CLI run as uid `1000`, with `cap_drop: ALL`, `no-new-privileges`, read-only root filesystem, `tmpfs` for writable scratch paths, and CPU, memory, and process limits.
- The host Docker socket is not mounted into the gateway in the default deployment.
- The optional sandbox overlay uses a private Docker-in-Docker sidecar so OpenClaw can create agent sandbox containers without receiving the host Docker socket.
- The secure OpenClaw config enables the bundled Codex plugin, forces the Codex harness for `codex/*` models, sandboxes all agent tool execution, disables elevated exec, and denies automation, node-control, and messaging tools by default.
- External OpenClaw plugin installation is disabled from chat commands by default. Install plugins deliberately from the CLI after review.

## Files

- `compose.yaml`: hardened OpenClaw gateway and CLI services.
- `compose.sandbox-dind.yaml`: optional Docker-in-Docker sandbox overlay.
- `Dockerfile.gateway`: adds the Docker CLI to the Phioranex OpenClaw image so the gateway can talk to the sandbox sidecar.
- `openclaw.secure-config.json`: readable policy baseline applied by `scripts/Apply-OpenClawSecureConfig.ps1`.
- `scripts/Test-OpenClawPrereqs.ps1`: blocks startup until Docker, Compose v2, daemon access, ports, and minimum Docker memory are checked.
- `scripts/Install-OpenClawSecure.ps1`: creates local runtime directories and `.env`, validates Compose, pulls/builds images, and optionally starts the gateway.
- `scripts/Apply-OpenClawSecureConfig.ps1`: applies the OpenClaw sandbox, Codex harness, and tool-policy baseline after onboarding.
- `scripts/Audit-OpenClawSecure.ps1`: writes a Markdown audit report under `reports/`.
- `scripts/Register-OpenClawAuditTask.ps1`: registers a daily Windows scheduled audit.

## Prerequisites

Install Docker Desktop or Docker Engine with Docker Compose v2. On Windows, Docker Desktop with the WSL2 backend is the practical path. Allocate at least 2 GB RAM to Docker; more is better if you build local images.

Run the local check before any install/start attempt:

```powershell
.\scripts\Test-OpenClawPrereqs.ps1
```

## Template Configuration

Before running this deployment from a fresh clone, review `.env.example` and create a local `.env`. The install script creates `.env` automatically when it is missing, including a generated gateway token.

Values most users may need to change:

- `OPENCLAW_GATEWAY_TOKEN`: required secret for gateway access. Use a unique random value and never commit `.env`.
- `OPENCLAW_GATEWAY_HOST`: defaults to `127.0.0.1`; keep this for local-only access.
- `OPENCLAW_GATEWAY_PORT` and `OPENCLAW_BRIDGE_PORT`: change only if the defaults conflict with another local service.
- `OPENCLAW_GATEWAY_BIND`: controls the gateway bind mode inside OpenClaw; keep `lan` unless you understand the exposure model.
- `OPENCLAW_CONFIG_DIR`, `OPENCLAW_WORKSPACE_DIR`, and `OPENCLAW_CODEX_DIR`: local state directories. Use paths that are private to the machine running the gateway.
- `OPENCLAW_TZ`: set this to the operator's local timezone if audit timestamps should use local time.
- `OPENCLAW_IMAGE`: pin to a reviewed OpenClaw image tag or digest for repeatable deployments.
- `OPENCLAW_SANDBOX_GATEWAY_IMAGE`: optional; set only when using a custom locally built sandbox gateway image.

Do not commit generated runtime state, audit reports, local `.env` files, credentials, browser profiles, SSH keys, Docker config files, or account tokens. This repository's `.gitignore` excludes the default local state paths.

## Start Without Agent Sandbox

This starts only the hardened containerized gateway. Use it if you want to finish onboarding first, but do not let untrusted agents execute tools until the sandbox policy is applied.

```powershell
.\scripts\Install-OpenClawSecure.ps1
```

Open the local dashboard at `http://127.0.0.1:18789/`.

## Start With Docker-Backed Agent Sandbox

This is the intended secure mode for Codex/OpenClaw agent work. It builds a gateway image with the Docker CLI and starts a private Docker-in-Docker sidecar for sandbox containers.

```powershell
.\scripts\Install-OpenClawSecure.ps1 -WithSandbox
```

After onboarding, apply the secure OpenClaw policy:

```powershell
.\scripts\Apply-OpenClawSecureConfig.ps1 -UseSandboxOverlay
```

Verify effective sandboxing:

```powershell
docker compose -f compose.yaml -f compose.sandbox-dind.yaml run --rm openclaw-cli sandbox explain --json
```

## Plugin and Skill Access

The baseline enables the bundled `codex` plugin and uses `codex/gpt-5.4`, which routes embedded agent turns through the Codex harness when the Codex app-server/auth requirements are met. OpenClaw plugins and skills remain OpenClaw-managed, but tool execution is constrained by sandbox and tool policy.

For additional plugins:

1. Review the plugin source/package.
2. Install from the CLI, not from chat.
3. Re-run the audit.
4. Add only the required tools to allowlists.

## Audits

Run an audit manually:

```powershell
.\scripts\Audit-OpenClawSecure.ps1 -UseSandboxOverlay
```

Register a daily audit:

```powershell
.\scripts\Register-OpenClawAuditTask.ps1 -UseSandboxOverlay
```

The audit checks Compose validation, runtime hardening controls, whether the host Docker socket is mounted, health status, and Docker Scout or Trivy image CVEs when available.

## Source Notes

- The Phioranex OpenClaw Docker repo provides the ready-made container image and installer flow; this deployment uses the image, not the one-line installer, so we can keep local hardening controls in source.
- OpenClaw Docker docs require Docker Desktop or Engine plus Compose v2, recommend at least 2 GB RAM, document health endpoints, persistence paths, and sandbox bootstrap.
- OpenClaw sandboxing docs state that tool execution can run in isolated Docker containers, while the gateway itself is not sandboxed.
- OpenClaw tool policy docs distinguish sandboxing, allow/deny policy, and elevated exec; deny policy is the hard stop.
- OpenClaw Codex Harness docs require the bundled `codex` plugin, Codex app-server `0.118.0` or newer, and Codex auth for app-server execution.
- Docker docs describe default seccomp as an allowlist and Docker Scout as SBOM-backed vulnerability analysis.
