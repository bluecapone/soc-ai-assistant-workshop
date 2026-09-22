# SOC AI Assistant Workshop

Build a SOC triage agent and run it against an intrusion you launch on your own laptop. This repo is your workshop folder: the guide, the files you copy during the exercises, and the Docker lab.

Read **[guide.pdf](guide.pdf)** first. It has every exercise, in order, with what you should see at each step.

## What you need

- Docker with Docker Compose. Install [Docker Desktop](https://docs.docker.com/desktop/) and start it.
- 16 GB RAM and free disk for the containers.
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) installed.
- A gateway token, handed to you at the workshop.

## Run the lab

Clone this repo and enter the lab folder.

```bash
git clone https://github.com/bluecapone/soc-ai-assistant-workshop
cd soc-ai-assistant-workshop/lab
```

Start everything on macOS or Linux:

```bash
./scripts/macos-linux/start.sh
```

Start everything on Windows (PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\start.ps1
```

The first run pulls images and builds three services, so it takes a few minutes. It is safe to run again if you interrupt it. Wait for the `== Ready` block: it prints every address and login.

## What comes up

Five services, all on your laptop. Nothing is shared with the room.

| Service | Address | Login |
|---|---|---|
| Attack console | http://panel.localhost (or :8000) | none |
| Bank website | http://web.localhost (or :8080) | none |
| TheHive | http://thehive.localhost (or :9000) | `analyst@brucon.local` / `brucon2026` |
| Wazuh SIEM | http://wazuh.localhost (or :8443) | `admin` / `brucon2026` |
| n8n | http://n8n.localhost (or :5678) | `admin@brucon.local` / `Brucon2026` |

If a `*.localhost` name does not open, use the `:port` form. Your model calls route through the gateway using the token you were given.

## Stop and clean up

Run from the lab folder. Clean stops the containers and deletes the lab data. Your `.env` and the threat-intel lists stay.

macOS or Linux:

```bash
./scripts/macos-linux/clean.sh            # containers, volumes, generated state
./scripts/macos-linux/clean.sh --images   # also remove the built images and the build cache
./scripts/macos-linux/clean.sh --all      # also remove the pulled base images (a bare slate)
```

Windows (PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\clean.ps1           # containers, volumes, generated state
powershell -ExecutionPolicy Bypass -File .\scripts\windows\clean.ps1 -Images   # also remove the built images and the build cache
powershell -ExecutionPolicy Bypass -File .\scripts\windows\clean.ps1 -All       # also remove the pulled base images (a bare slate)
```

Use `--images` (`-Images`) to rebuild the workshop services from scratch without re-pulling several GB. Use `--all` (`-All`) only when you want nothing left behind, because the next start re-pulls the base images.

## What is in here

- `guide.pdf`: the workshop manual. Start here.
- `exercises/`: files the exercises tell you to copy.
- `lab/`: the Docker Compose lab and its start and clean scripts.
