# Sentinel

## Download for Windows

[**Download Sentinel Installer**](https://github.com/Maralbyek/Sentinel/releases/download/v1.0.1/Sentinel.Setup.1.0.1.exe) | [**Download Portable App**](https://github.com/Maralbyek/Sentinel/releases/download/v1.0.1/Sentinel.1.0.1.exe)

Install Sentinel with the first link to add it as a normal Windows application with Start Menu and Desktop shortcuts. Use the portable link to run it without installing. Both downloads include the Python security engine; Node.js and Python are not required.

Sentinel is a local Windows endpoint security monitor. Python collects live system data and applies the detection rules; Electron provides the desktop interface. No web server, cloud service, or database is required.

## Download Sentinel for Windows

Download the latest Windows installer from the [GitHub Releases page](https://github.com/Maralbyek/Sentinel/releases/latest). Run the downloaded installer and follow the prompts. It installs Sentinel as a normal Windows application, adds it to the Start Menu, and can create a Desktop shortcut.

The installer stores the app under the current user's local applications folder by default. No administrator access is required. The portable `.exe` is also available on the Releases page when you want to run Sentinel without installing it.

## Get the project

Repository: <https://github.com/Maralbyek/Sentinel>

Clone it with Git:

```powershell
git clone https://github.com/Maralbyek/Sentinel.git
cd Sentinel
```

## Run from source on Windows

Requirements:

- Windows 10 or later
- Node.js 20 or later
- Python 3.11 or later
- Git

In PowerShell, from the project folder:

```powershell
npm install
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
npm start
```

Click **Run scan** after the window opens. Some Windows Security event data may require starting the application with administrator privileges.

## Build a Windows installer yourself

After installing the dependencies above:

```powershell
npm run dist
```

The generated installer and portable executable appear in the `dist` folder. These builds include the bundled Python engine, so recipients do not need Node.js, Python, or the repository to run the released app.

The Python runtime and `.venv` are intentionally kept outside Git because virtual environments are machine-specific. Publish the generated files as GitHub Release assets so users can download and launch Sentinel directly.

## Test the Python engine

```powershell
\.venv\Scripts\python.exe -m src.engine
```

The command prints one JSON object containing processes, startup items, network connections, listening ports, drives, and findings.

## Project layout

- `main.js` - Electron main process and Python subprocess bridge
- `preload.js` - restricted IPC API exposed to the renderer
- `src/collectors/` - Windows data collectors
- `src/rules/` - security detection rules
- `src/engine.py` - scan orchestration and JSON output
- `src/ui/` - desktop interface