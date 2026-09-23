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
    const pythonPath = path.join(__dirname, '.venv', 'Scripts', 'python.exe');
    const python = spawn(pythonPath, ['-m', 'src.engine'], { cwd: __dirname });
    
    let output = '';
    let errorOutput = '';

    python.stdout.on('data', (data) => { output += data.toString(); });
    python.stderr.on('data', (data) => { errorOutput += data.toString(); });

    python.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`Python exited with code ${code}: ${errorOutput}`));
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