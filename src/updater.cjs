'use strict';

const checkableStatuses = new Set(['idle', 'up-to-date', 'available', 'error']);
const missingFeedCodes = new Set([
  'ENOENT',
  'ERR_UPDATER_CHANNEL_FILE_NOT_FOUND',
  'ERR_UPDATER_LATEST_VERSION_NOT_FOUND',
  'ERR_UPDATER_NO_PUBLISHED_VERSIONS',
]);

const installFailedMessage = '无法启动更新安装程序，请重试。';

function createUpdater({ isPackaged, currentVersion, onState = () => {}, updater }) {
  let state = {
    status: isPackaged ? 'idle' : 'unsupported',
    currentVersion,
    availableVersion: null,
    progress: null,
    message: isPackaged ? '' : '请在已安装的 Windows 版本中检查更新。',
  };

  const getState = () => ({ ...state });

  function setState(changes) {
    state = { ...state, ...changes };
    onState(getState());
  }

  if (isPackaged) {
    updater ??= require('electron-updater').autoUpdater;
    updater.autoDownload = false;
    updater.autoInstallOnAppQuit = false;
    updater.allowPrerelease = false;
    updater.allowDowngrade = false;
    updater.disableWebInstaller = true;

    updater.on('download-progress', ({ percent }) => {
      if (state.status !== 'downloading' || !Number.isFinite(percent)) return;
      const progress = Math.min(100, Math.max(0, Math.round(percent)));
      if (progress !== state.progress) setState({ progress });
    });

    updater.on('error', () => {
      // Check and download errors reject their respective promises. Installation reports errors through this event.
      if (state.status === 'installing') {
        setState({ status: 'downloaded', message: installFailedMessage });
      }
    });
  }

  async function check() {
    if (!checkableStatuses.has(state.status)) return getState();

    setState({ status: 'checking', availableVersion: null, progress: null, message: '' });
    try {
      const result = await updater.checkForUpdates();
      if (!result) {
        setState({ status: 'error', message: '更新服务暂不可用，请稍后重试。' });
      } else if (result.isUpdateAvailable) {
        setState({ status: 'available', availableVersion: result.updateInfo.version });
      } else {
        setState({ status: 'up-to-date' });
      }
    } catch (error) {
      const message = missingFeedCodes.has(error?.code)
        ? '暂未找到更新发布信息，请稍后重试。'
        : '检查更新失败。请检查网络连接后重试。';
      setState({ status: 'error', message });
    }
    return getState();
  }

  async function download() {
    if (state.status !== 'available') return getState();

    setState({ status: 'downloading', progress: 0, message: '' });
    try {
      await updater.downloadUpdate();
      setState({ status: 'downloaded', progress: 100 });
    } catch {
      setState({ status: 'available', progress: null, message: '下载或校验更新失败，请重试。' });
    }
    return getState();
  }

  async function install() {
    if (state.status !== 'downloaded') return getState();

    setState({ status: 'installing', message: '' });
    try {
      updater.quitAndInstall(true, true);
    } catch {
      setState({ status: 'downloaded', message: installFailedMessage });
    }
    return getState();
  }

  return { getState, check, download, install };
}

module.exports = { createUpdater };
