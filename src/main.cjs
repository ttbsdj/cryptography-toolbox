'use strict';

const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { app, BrowserWindow, Menu, clipboard, ipcMain } = require('electron');
const { runCrypto } = require('./crypto.cjs');
const { createUpdater } = require('./updater.cjs');

const pagePath = path.join(__dirname, 'index.html');
const pageUrl = pathToFileURL(pagePath).href;
const MAX_TEXT_LENGTH = 2_200_000;
let mainWindow;
let cryptoBusy = false;

function createWindow() {
  const window = new BrowserWindow({
    width: 1240,
    height: 890,
    minWidth: 740,
    minHeight: 640,
    backgroundColor: '#101719',
    icon: path.join(__dirname, 'app-icon.png'),
    autoHideMenuBar: true,
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  mainWindow = window;

  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  window.webContents.on('will-navigate', (event) => event.preventDefault());
  window.webContents.session.setPermissionRequestHandler((_contents, _permission, respond) => respond(false));
  window.webContents.session.setPermissionCheckHandler(() => false);
  window.once('ready-to-show', () => window.show());
  window.on('closed', () => { mainWindow = undefined; });
  window.loadFile(pagePath);
}

function setHandler(channel, handler) {
  ipcMain.handle(channel, (event, ...args) => {
    if (!mainWindow || event.sender !== mainWindow.webContents ||
        event.senderFrame !== mainWindow.webContents.mainFrame || event.senderFrame.url !== pageUrl) {
      throw new Error('请求来源无效。');
    }
    return handler(...args);
  });
}

async function run(payload) {
  if (cryptoBusy) return { error: '正在处理，请稍后再试。' };
  if (!payload || typeof payload !== 'object' || typeof payload.input !== 'string' ||
      payload.input.length > MAX_TEXT_LENGTH) {
    return { error: '输入内容无效或长度超限。' };
  }

  cryptoBusy = true;
  try {
    return await runCrypto({
      algorithm: payload.algorithm,
      operation: payload.operation,
      input: payload.input,
      key: payload.key,
      keyFormat: payload.keyFormat,
      encoding: payload.encoding,
      expected: payload.expected,
      format: payload.format,
      iv: payload.iv,
      tag: payload.tag,
    });
  } catch (error) {
    return { error: error?.message || '处理失败，请检查输入。' };
  } finally {
    cryptoBusy = false;
  }
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (!mainWindow) return;
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.focus();
  });

  app.whenReady().then(() => {
    Menu.setApplicationMenu(null);
    app.setAppUserModelId('com.cryptographytoolbox.desktop');

    const updater = createUpdater({
      isPackaged: app.isPackaged,
      currentVersion: app.getVersion(),
      onState(state) {
        if (mainWindow && !mainWindow.webContents.isDestroyed()) {
          mainWindow.webContents.send('updates:state', state);
        }
      },
    });

    setHandler('crypto:run', run);
    setHandler('clipboard:write', (value) => {
      if (typeof value !== 'string' || value.length > MAX_TEXT_LENGTH) {
        throw new Error('复制内容无效或长度超限。');
      }
      clipboard.writeText(value);
    });
    setHandler('updates:get', updater.getState);
    setHandler('updates:check', updater.check);
    setHandler('updates:download', updater.download);
    setHandler('updates:install', updater.install);
    createWindow();
  });

  app.on('window-all-closed', () => app.quit());
}
