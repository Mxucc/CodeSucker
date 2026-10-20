import { app, BrowserWindow, ipcMain, screen, type WebContents } from 'electron';
import * as path from 'node:path';
import { isPipelineBusy, registerPipelineIpc, shutdownPipeline } from './pipeline';
import {
  loadWindowState, minimumSizeForBounds, showRestoredWindow,
  WINDOW_STATE_CONFIG_NAME, WindowStateTracker,
} from './window-state';
import { windowChromeOptions } from './window-chrome';
import { registerUpdateIpc, UpdateService } from './update-service';

let win: BrowserWindow | null = null;
let updateService: UpdateService | null = null;

app.setName('CodeDoc');
app.enableSandbox();

function isTrustedRenderer(sender: WebContents): boolean {
  return win !== null && !win.isDestroyed() && sender === win.webContents;
}

function createWindow() {
  const stateFile = path.join(app.getPath('userData'), WINDOW_STATE_CONFIG_NAME);
  const restoredState = loadWindowState(stateFile, screen);
  const minimumSize = minimumSizeForBounds(restoredState.bounds);
  const createdWindow = new BrowserWindow({
    ...restoredState.bounds,
    minWidth: minimumSize.width,
    minHeight: minimumSize.height,
    ...windowChromeOptions(process.platform),
    show: false,
    icon: path.join(__dirname, '../../build/icon.png'),
    backgroundColor: '#f4f4f5',
    webPreferences: {
      preload: path.join(__dirname, '../preload/index.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  win = createdWindow;

  new WindowStateTracker(stateFile, createdWindow, screen, restoredState);
  createdWindow.on('ready-to-show', () => {
    showRestoredWindow(createdWindow, restoredState);
    updateService?.scheduleAutomaticCheck();
  });

  // 导航与新窗口兜底：CSP 是唯一的前端防线，一旦 renderer 出现 XSS，
  // 没有这两处拦截就可以把窗口导航到外部页面，或以新窗口打开任意地址。
  // 应用是单页本地界面，除自身渲染入口外不应发生任何导航。
  createdWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  createdWindow.webContents.on('will-navigate', (event, url) => {
    const current = createdWindow.webContents.getURL();
    if (url !== current) event.preventDefault();
  });
  createdWindow.webContents.on('will-attach-webview', (event) => event.preventDefault());

  if (process.env.ELECTRON_RENDERER_URL) {
    createdWindow.loadURL(process.env.ELECTRON_RENDERER_URL);
  } else {
    createdWindow.loadFile(path.join(__dirname, '../renderer/index.html'));
  }
}

app.whenReady().then(() => {
  registerPipelineIpc(isTrustedRenderer);
  updateService = new UpdateService({
    appVersion: app.getVersion(),
    isPackaged: app.isPackaged,
    logFile: path.join(app.getPath('logs'), 'updater.log'),
    canInstall: () => !isPipelineBusy(),
    broadcast: (state) => {
      if (win && !win.isDestroyed()) win.webContents.send('update:state', state);
    },
  });
  registerUpdateIpc(updateService, isTrustedRenderer);

  ipcMain.on('win:minimize', (event) => {
    if (!isTrustedRenderer(event.sender)) return;
    win?.minimize();
  });
  ipcMain.on('win:maximize', (event) => {
    if (!isTrustedRenderer(event.sender)) return;
    if (win?.isMaximized()) win.unmaximize(); else win?.maximize();
  });
  ipcMain.on('win:close', (event) => {
    if (!isTrustedRenderer(event.sender)) return;
    win?.close();
  });

  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  void shutdownPipeline();
});
