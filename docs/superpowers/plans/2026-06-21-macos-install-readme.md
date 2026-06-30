# macOS Installation README Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give Apple Silicon users complete, matching installation and troubleshooting instructions on GitHub and inside the macOS release ZIP.

**Architecture:** Add a self-contained macOS section to the root Markdown README and expand the existing plain-text Mac guide with the same command sequence. Keep this change documentation-only and validate command consistency mechanically before committing.

**Tech Stack:** Markdown, plain text, zsh command examples, Git

---

### Task 1: Add macOS instructions to the project README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add the Apple Silicon release setup section**

Add a section after the Windows release-download instructions covering:

```bash
brew install wireguard-tools bash
sudo mkdir -p /opt/homebrew/etc/wireguard
sudo cp "/path/to/your-vpn.conf" /opt/homebrew/etc/wireguard/
sudo chmod 600 /opt/homebrew/etc/wireguard/*.conf
cd "$HOME/Downloads/wireguard-split-tunnel-mac-arm64"
./check-mac-deps.sh
xattr -dr com.apple.quarantine WireguardSplitTunnel.app
open WireguardSplitTunnel.app
```

Explain that the ZIP does not contain a `.conf` file because it contains private credentials. Add the direct executable fallback:

```bash
"$HOME/Downloads/wireguard-split-tunnel-mac-arm64/WireguardSplitTunnel.app/Contents/MacOS/WireguardSplitTunnel"
```

Distinguish launch failures from tunnel failures: launch failures use the quarantine and direct-launch steps; tunnel failures require a valid configuration and a successful dependency check.

- [ ] **Step 2: Validate the Markdown change**

Run:

```bash
git diff --check -- README.md
rg -n "macOS Apple Silicon|check-mac-deps|com.apple.quarantine|Contents/MacOS/WireguardSplitTunnel" README.md
```

Expected: `git diff --check` exits 0, and all four topics appear in the new section.

### Task 2: Align the packaged macOS guide

**Files:**
- Modify: `docs/README-Mac.txt`

- [ ] **Step 1: Expand setup and troubleshooting**

Add the missing directory creation and configuration-copy commands:

```text
sudo mkdir -p /opt/homebrew/etc/wireguard
sudo cp "/path/to/your-vpn.conf" /opt/homebrew/etc/wireguard/
sudo chmod 600 /opt/homebrew/etc/wireguard/*.conf
```

Retain the dependency check and quarantine commands. Add the direct executable fallback and separate troubleshooting headings for application launch and tunnel enablement.

- [ ] **Step 2: Validate command consistency**

Run:

```bash
for token in "brew install wireguard-tools bash" "sudo mkdir -p /opt/homebrew/etc/wireguard" "check-mac-deps.sh" "com.apple.quarantine" "Contents/MacOS/WireguardSplitTunnel"; do
  rg -F "$token" README.md docs/README-Mac.txt
done
```

Expected: every token is found in both files.

### Task 3: Verify, commit, and publish

**Files:**
- Modify: `README.md`
- Modify: `docs/README-Mac.txt`
- Create: `docs/superpowers/plans/2026-06-21-macos-install-readme.md`

- [ ] **Step 1: Inspect the final documentation diff**

Run:

```bash
git diff --check
git diff -- README.md docs/README-Mac.txt docs/superpowers/plans/2026-06-21-macos-install-readme.md
git status --short
```

Expected: no whitespace errors, only the three planned documentation paths are uncommitted, and no private `.conf` content appears.

- [ ] **Step 2: Commit the implementation**

Run:

```bash
git add README.md docs/README-Mac.txt docs/superpowers/plans/2026-06-21-macos-install-readme.md
git commit -m "docs: improve macOS installation guidance"
```

Expected: one documentation commit is created.

- [ ] **Step 3: Push and verify GitHub synchronization**

Run:

```bash
git push origin main
git status --short --branch
git rev-parse HEAD
git rev-parse origin/main
```

Expected: push exits 0, the branch reports `main...origin/main` with no divergence, and both revision hashes match.
