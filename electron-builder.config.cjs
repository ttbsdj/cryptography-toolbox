'use strict';

const { execFileSync } = require('node:child_process');

function repositoryName() {
  if (process.env.GITHUB_REPOSITORY) {
    return process.env.GITHUB_REPOSITORY;
  }

  try {
    const origin = execFileSync('git', ['remote', 'get-url', 'origin'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      windowsHide: true,
    }).trim();
    return origin.match(/^(?:https:\/\/github\.com\/|git@github\.com:|ssh:\/\/git@github\.com\/)([^/]+\/[^/]+?)(?:\.git)?\/?$/i)?.[1];
  } catch {
    return undefined;
  }
}

const repository = repositoryName();
if (repository && !/^[a-z\d-]+\/[a-z\d_.-]+$/i.test(repository)) {
  throw new Error('GITHUB_REPOSITORY 必须为 owner/repo。');
}
const [owner, repo] = repository ? repository.split('/') : [];

module.exports = {
  appId: 'com.cryptographytoolbox.desktop',
  directories: { output: 'dist' },
  files: ['src/**/*', 'package.json'],
  artifactName: 'Cryptography-Toolbox-Setup-${version}.${ext}',
  publish: owner ? { provider: 'github', owner, repo, private: false } : null,
  win: {
    target: 'nsis',
    icon: 'build/icon.ico',
  },
  nsis: {
    oneClick: false,
    perMachine: false,
    allowToChangeInstallationDirectory: true,
    installerLanguages: ['zh_CN', 'en_US'],
  },
};
