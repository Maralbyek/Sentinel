# Sentinel

> A local Windows endpoint security observatory for seeing what is running, what is connecting, and what deserves attention.

[![Release](https://img.shields.io/github/v/release/Maralbyek/Sentinel?label=latest%20release&color=157e87)](https://github.com/Maralbyek/Sentinel/releases/latest)
[![Platform](https://img.shields.io/badge/platform-Windows-17242d)](https://github.com/Maralbyek/Sentinel)
[![Privacy](https://img.shields.io/badge/data-local%20only-368667)](https://github.com/Maralbyek/Sentinel)

## Download Sentinel for Windows

| Option | Download | Use it when |
| --- | --- | --- |
| Installer | [**Sentinel.Setup.1.0.3.exe**](https://github.com/Maralbyek/Sentinel/releases/download/v1.0.3/Sentinel.Setup.1.0.3.exe) | You want Start Menu and Desktop shortcuts |
| Portable | [**Sentinel.1.0.3.exe**](https://github.com/Maralbyek/Sentinel/releases/download/v1.0.3/Sentinel.1.0.3.exe) | You want to run it without installing |

Both files are built from the current `main` branch and include the bundled Python engine. The app reads the local Windows machine only: no server, cloud relay, database, or account is involved.

> Windows SmartScreen may show a warning because this portfolio release is not code-signed yet. The files above are the official assets published in this repository. A trusted Windows signing certificate is planned for a later release.

## What it looks like

![Sentinel overview](https://github.com/Maralbyek/Sentinel/blob/main/docs/Screenshot%202026-09-24%20180202.png)

The overview is designed as a readable security report rather than a wall of tables. It includes an inspection path, signal map, live telemetry bars, posture ring, process activity plot, network map, evidence stack, local search, and report notes.

## What Sentinel checks

- Running processes, CPU, memory, users, and executable paths
- Startup and persistence entries
- Active network connections and listening ports
- Drive capacity and storage summaries
- Windows Security event data where permissions allow it
- Defender, firewall, and hosts-file status
- Rules for suspicious locations, orphaned startup items, exposed services, and security controls

## Architecture

Python owns the security work. Electron is only the desktop shell.

```text
Windows machine
      |
      v
Python collectors  --->  raw facts
      |
      v
Python rules        --->  findings
      |
      v
src.engine          --->  one JSON scan result
      |
      v
Electron main.js    --->  IPC bridge
      |
      v
Renderer UI         --->  report, diagrams, tables
```

The renderer never reimplements detection logic. It receives the JSON result through the restricted API exposed by `preload.js`.

## Project structure

```text
sentinel/
├── main.js                         Electron main process and Python bridge
├── preload.js                      Restricted contextBridge API
├── package.json                    Run and Windows packaging scripts
├── requirements.txt                Python dependencies
├── README.md                       Project documentation
├── docs/
│   └── sentinel-overview.png       Current UI screenshot
├── src/
│   ├── engine.py                   Scan orchestration and JSON output
│   ├── collectors/
│   │   ├── processes.py            Running process facts
│   │   ├── startup.py              Startup and persistence facts
│   │   ├── network.py               Connections and listening ports
│   │   ├── storage.py              Drives and storage facts
│   │   ├── events.py                Windows Security events
│   │   └── security_status.py       Defender, firewall, hosts file
│   ├── rules/
│   │   └── detectors.py             Security rules and findings
│   └── ui/
│       ├── index.html               Report layout
│       ├── renderer.js              Navigation, search, rendering
│       └── style.css                Glass observatory visual system
└── .github/workflows/
    └── windows-release.yml          Automated Windows release build
```

## Run from source

Requirements: Windows 10 or later, Node.js 20+, Python 3.11+, and Git.

```powershell
git clone https://github.com/Maralbyek/Sentinel.git
cd Sentinel
npm install
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
npm start
```

Click **Run scan** to collect a live report. Some Security event data may require administrator privileges.

## Build a Windows release

```powershell
npm run dist
```

The installer and portable executable are written to `dist/`. The build bundles the Python engine with PyInstaller and packages both NSIS and portable Windows targets through Electron Builder.

To publish a release, update the version in `package.json`, build, create a matching `v*` tag, and upload the two generated `.exe` files to GitHub Releases. The included GitHub Actions workflow can also build tagged releases automatically.

## Test the Python engine directly

```powershell
.\.venv\Scripts\python.exe -m src.engine
```

The command prints one JSON object containing processes, startup items, connections, listening ports, drives, and findings.

## Privacy and permissions

Sentinel runs locally and does not send scan data anywhere. Windows may restrict access to some process details or Security event records unless the application is started with elevated permissions. Only run downloaded binaries from the official repository or build the project from source yourself.

## Current release

**v1.0.3** · [Release notes and downloads](https://github.com/Maralbyek/Sentinel/releases/tag/v1.0.3)
