const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('sentinel', {
  runScan: () => ipcRenderer.invoke('run:scan')
});