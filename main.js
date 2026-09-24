const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  mainWindow.loadFile(path.join(__dirname, 'src', 'ui', 'index.html'));
}

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// Runs the full Python engine and returns its JSON result to the UI
ipcMain.handle('run:scan', async () => {
  return new Promise((resolve, reject) => {
    const pythonPath = app.isPackaged
      ? path.join(process.resourcesPath, 'sentinel-engine.exe')
      : path.join(__dirname, '.venv', 'Scripts', 'python.exe');
    const pythonArgs = app.isPackaged ? [] : ['-m', 'src.engine'];
    const python = spawn(pythonPath, pythonArgs, {
      cwd: app.isPackaged ? process.resourcesPath : __dirname,
      windowsHide: true
    });
    
    let output = '';
    let errorOutput = '';

    python.stdout.on('data', (data) => { output += data.toString(); });
    python.stderr.on('data', (data) => { errorOutput += data.toString(); });

    python.on('error', (error) => {
      reject(new Error(`Could not start the scan engine: ${error.message}`));
    });

    python.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`Scan engine exited with code ${code}: ${errorOutput || 'No details were returned.'}`));
        return;
      }
      try {
        resolve(JSON.parse(output));
      } catch (e) {
        reject(new Error(`Failed to parse Python output: ${e.message}`));
      }
    });
  });
});

 ipcMain.handle('open:location', async (event, targetPath) => {
  shell.showItemInFolder(targetPath);
});