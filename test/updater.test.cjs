'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const test = require('node:test');
const { createUpdater } = require('../src/updater.cjs');

const updateResult = { isUpdateAvailable: true, updateInfo: { version: '1.1.0' } };

test('development builds do not initialize or contact the updater', async () => {
  const service = createUpdater({ isPackaged: false, currentVersion: '1.0.0' });

  assert.equal((await service.check()).status, 'unsupported');
  assert.equal((await service.download()).status, 'unsupported');
  assert.equal((await service.install()).status, 'unsupported');
});

test('checks and downloads once, then installs only when requested', async () => {
  const states = [];
  const updater = new EventEmitter();
  const service = createUpdater({ isPackaged: true, currentVersion: '1.0.0', onState: (state) => states.push(state), updater });
  let checkCount = 0;
  let downloadCount = 0;
  let installCount = 0;
  updater.checkForUpdates = async () => {
    checkCount++;
    return updateResult;
  };
  updater.downloadUpdate = async () => {
    downloadCount++;
    updater.emit('download-progress', { percent: 38.3 });
  };
  updater.quitAndInstall = (silent, restart) => {
    installCount++;
    assert.equal(silent, true);
    assert.equal(restart, true);
  };

  assert.equal(updater.autoDownload, false);
  assert.equal(updater.autoInstallOnAppQuit, false);
  assert.equal(updater.allowPrerelease, false);
  assert.equal(updater.allowDowngrade, false);
  assert.equal(updater.disableWebInstaller, true);
  assert.equal((await service.download()).status, 'idle');
  assert.equal((await service.install()).status, 'idle');
  const [checked, inFlightCheck] = await Promise.all([service.check(), service.check()]);
  assert.equal(checked.availableVersion, '1.1.0');
  assert.equal(inFlightCheck.status, 'checking');

  const [downloaded, inFlightDownload] = await Promise.all([service.download(), service.download()]);
  assert.equal(downloaded.progress, 100);
  assert.equal(inFlightDownload.status, 'downloading');
  assert.equal((await service.check()).status, 'downloaded');
  assert.equal(installCount, 0);
  assert.equal((await service.install()).status, 'installing');
  assert.equal((await service.install()).status, 'installing');
  assert.equal(checkCount, 1);
  assert.equal(downloadCount, 1);
  assert.equal(installCount, 1);
  assert.deepEqual(states.map(({ status, progress }) => [status, progress]), [
    ['checking', null], ['available', null], ['downloading', 0], ['downloading', 38],
    ['downloaded', 100], ['installing', 100],
  ]);
});

test('reports missing releases, keeps failures retryable and does not expose errors', async () => {
  const updater = new EventEmitter();
  const service = createUpdater({ isPackaged: true, currentVersion: '1.0.0', updater });
  const internalError = Object.assign(new Error('internal detail'), { code: 'ERR_UPDATER_CHANNEL_FILE_NOT_FOUND' });
  updater.checkForUpdates = async () => {
    updater.emit('error', internalError);
    throw internalError;
  };

  const checkError = await service.check();
  assert.equal(checkError.status, 'error');
  assert.match(checkError.message, /发布信息/);
  updater.checkForUpdates = async () => ({ ...updateResult, isUpdateAvailable: false });
  assert.equal((await service.check()).status, 'up-to-date');

  updater.checkForUpdates = async () => updateResult;
  await service.check();
  updater.downloadUpdate = async () => { throw internalError; };
  const downloadError = await service.download();
  assert.equal(downloadError.status, 'available');
  assert.match(downloadError.message, /请重试/);
  assert.equal(downloadError.progress, null);

  updater.downloadUpdate = async () => {};
  assert.equal((await service.download()).status, 'downloaded');
  updater.quitAndInstall = () => updater.emit('error', internalError);
  const installError = await service.install();
  assert.equal(installError.status, 'downloaded');
  assert.match(installError.message, /请重试/);
});
