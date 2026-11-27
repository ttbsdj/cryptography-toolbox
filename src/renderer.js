'use strict';

const api = window.cryptography;
const byId = (id) => document.getElementById(id);
const form = byId('workbench');
const input = byId('input');
const output = byId('output');
const mode = byId('mode');
const format = byId('format');
const keyFormat = byId('key-format');
const key = byId('key');
const iv = byId('iv');
const tag = byId('tag');
const cipherEncoding = byId('cipher-encoding');
const hashEncoding = byId('hash-encoding');
const expected = byId('expected');
const reverseRadio = form.querySelector('input[name="direction"][value="reverse"]');
const clearButton = byId('clear');
const swapButton = byId('swap');
const copyButton = byId('copy');
const runButton = byId('run');
const feedback = byId('feedback');
const verification = byId('verification');
const metadata = byId('metadata');
const resultIv = byId('result-iv');
const resultTag = byId('result-tag');
const encoder = new TextEncoder();

let lastResult = null;
let inputRevision = 0;
let running = false;

function updateInputSize() {
  byId('input-size').textContent = `${encoder.encode(input.value).byteLength.toLocaleString('zh-CN')} 字节`;
  clearButton.disabled = !input.value && !lastResult;
}

function showFeedback(message = '', isError = false) {
  feedback.textContent = message;
  feedback.classList.toggle('error', isError);
}

function clearResult() {
  inputRevision += 1;
  lastResult = null;
  output.value = '';
  byId('output-size').textContent = '0 字节';
  resultIv.value = '';
  resultTag.value = '';
  metadata.hidden = true;
  verification.hidden = true;
  copyButton.disabled = true;
  swapButton.disabled = true;
  showFeedback();
  updateInputSize();
}

function renderFields() {
  const family = form.elements.namedItem('algorithm').value;
  const hash = family === 'sm3';
  const reverse = reverseRadio.checked;
  const gcm = family === 'aes' && mode.value === 'aes-gcm';
  const raw = format.value === 'raw';

  byId('forward-label').textContent = hash ? '计算摘要' : '加密';
  byId('reverse-label').textContent = hash ? '校验摘要' : '解密';
  runButton.textContent = running
    ? '处理中…'
    : byId(reverse ? 'reverse-label' : 'forward-label').textContent;
  runButton.disabled = running;
  byId('input-label').textContent = hash ? '输入原文' : reverse ? '输入密文' : '输入明文';
  byId('output-label').textContent = hash ? '计算出的摘要' : reverse ? '输出明文' : '输出密文';
  input.placeholder = hash ? '在这里输入或粘贴原文…' : reverse ? '在这里粘贴密文…' : '在这里输入或粘贴明文…';
  swapButton.hidden = hash;
  byId('cipher-fields').hidden = hash;
  byId('hash-fields').hidden = !hash;
  byId('expected-field').hidden = !reverse;
  mode.hidden = family === 'sm4';
  byId('sm4-mode').hidden = family !== 'sm4';
  byId('iv-field').hidden = !raw;
  byId('tag-field').hidden = !raw || !gcm || !reverse;
  keyFormat.options[0].disabled = raw;
  if (raw && keyFormat.value === 'password') {
    keyFormat.value = 'hex';
    key.value = '';
  }

  const password = keyFormat.value === 'password';
  byId('key-label').textContent = password ? '口令' : '密钥';
  key.placeholder = password ? '输入口令' : `输入 ${keyFormat.value === 'hex' ? 'Hex' : 'Base64'} 密钥`;
  const ivDigits = gcm ? 24 : 32;
  iv.placeholder = reverse ? `输入 ${ivDigits} 个十六进制字符` : '留空时自动生成';
  byId('settings-hint').textContent = settingsHint({ family, hash, reverse, gcm, raw, password, ivDigits });
}

function settingsHint({ family, hash, reverse, gcm, raw, password, ivDigits }) {
  if (hash) {
    return reverse
      ? '将原文计算出的摘要与预期摘要比较。'
      : 'SM3 生成 256 位摘要，可用于检查文本是否发生变化。';
  }
  const keyDescription = password
    ? '解密时请使用相同口令。'
    : family === 'aes' ? 'AES 密钥长度支持 16、24 或 32 字节。' : 'SM4 密钥长度为 16 字节。';
  if (!raw) {
    return `密文包包含解密所需的参数及完整性校验数据。${keyDescription}`;
  }
  const ivDescription = reverse
    ? `需要原始初始向量（${ivDigits} 个十六进制字符）${gcm ? '和认证标签' : ''}。`
    : `初始向量留空时会自动生成。同一密钥下请勿复用。请保存初始向量${gcm ? '和认证标签' : ''}。`;
  return `${keyDescription}${ivDescription}${gcm ? '' : 'CBC 模式无法校验密文完整性。'}`;
}

function requestPayload() {
  const family = form.elements.namedItem('algorithm').value;
  const reverse = reverseRadio.checked;
  if (family === 'sm3') {
    return {
      algorithm: 'sm3',
      operation: reverse ? 'verify' : 'hash',
      input: input.value,
      expected: expected.value,
      encoding: hashEncoding.value
    };
  }
  return {
    algorithm: family === 'sm4' ? 'sm4-cbc' : mode.value,
    operation: reverse ? 'decrypt' : 'encrypt',
    input: input.value,
    key: key.value,
    keyFormat: keyFormat.value,
    format: format.value,
    encoding: cipherEncoding.value,
    iv: iv.value,
    tag: tag.value
  };
}

function showResult(result) {
  lastResult = result;
  output.value = result.output;
  byId('output-size').textContent = `${encoder.encode(result.output).byteLength.toLocaleString('zh-CN')} 字节`;
  copyButton.disabled = !result.output;
  swapButton.disabled = false;
  clearButton.disabled = false;

  resultIv.value = result.iv || '';
  resultTag.value = result.tag || '';
  byId('result-iv-row').hidden = !result.iv;
  byId('result-tag-row').hidden = !result.tag;
  metadata.hidden = !result.iv && !result.tag;

  verification.hidden = typeof result.verified !== 'boolean';
  if (!verification.hidden) {
    verification.textContent = result.verified ? '摘要一致' : '摘要不一致';
    verification.classList.toggle('unmatched', !result.verified);
    showFeedback(result.verified ? '校验通过。' : '校验未通过，计算出的摘要与预期不同。', !result.verified);
    return;
  }
  showFeedback('处理完成。');
}

async function run(event) {
  event.preventDefault();
  if (running) return;
  clearResult();
  const revision = inputRevision;
  running = true;
  renderFields();
  try {
    if (!api) throw new Error('无法连接到应用，请重新启动。');
    const result = await api.run(requestPayload());
    if (result?.error) throw new Error(result.error);
    if (typeof result?.output !== 'string') throw new Error('应用返回了无效的处理结果。');
    if (revision === inputRevision) showResult(result);
  } catch (error) {
    if (revision === inputRevision) {
      const message = error.message?.replace(/^Error invoking remote method '[^']+': (?:Error: )?/, '');
      showFeedback(message || '处理失败。', true);
    }
  } finally {
    running = false;
    renderFields();
  }
}

async function copyText(text, successMessage) {
  const revision = inputRevision;
  try {
    await api.copyText(text);
    if (revision === inputRevision) showFeedback(successMessage);
  } catch {
    if (revision === inputRevision) showFeedback('复制失败，请选中文本后手动复制。', true);
  }
}

form.addEventListener('submit', run);
form.addEventListener('input', (event) => {
  if (event.target.matches('textarea:not([readonly]), input:not([type="radio"]):not([readonly])')) {
    clearResult();
  }
});
form.addEventListener('change', (event) => {
  if (!event.target.matches('select, input[type="radio"]')) return;
  if (event.target.name === 'direction' && !reverseRadio.checked) {
    iv.value = '';
    tag.value = '';
  }
  clearResult();
  renderFields();
});

clearButton.addEventListener('click', () => {
  input.value = '';
  clearResult();
  input.focus();
});

swapButton.addEventListener('click', () => {
  if (!lastResult) return;
  const decrypting = !reverseRadio.checked;
  form.elements.namedItem('direction').value = decrypting ? 'reverse' : 'forward';
  input.value = lastResult.output;
  iv.value = decrypting ? lastResult.iv || '' : '';
  tag.value = decrypting ? lastResult.tag || '' : '';
  clearResult();
  renderFields();
  input.focus();
});

copyButton.addEventListener('click', () => copyText(output.value, '已复制结果。'));
byId('copy-iv').addEventListener('click', () => copyText(resultIv.value, '已复制初始向量。'));
byId('copy-tag').addEventListener('click', () => copyText(resultTag.value, '已复制认证标签。'));
byId('toggle-key').addEventListener('click', (event) => {
  const masked = key.type === 'password';
  key.type = masked ? 'text' : 'password';
  event.currentTarget.textContent = masked ? '隐藏' : '显示';
  event.currentTarget.setAttribute('aria-pressed', String(masked));
});

const updateDialog = byId('update-dialog');
const updateAction = byId('update-action');
const progress = byId('progress');

let updateState = { status: 'idle', currentVersion: null, availableVersion: null, progress: null, message: '' };
let updateRevision = 0;
let updatePending = false;

const updateLabels = {
  idle: { title: '准备检查更新', action: '检查更新', method: 'checkForUpdates' },
  unsupported: { title: '当前版本无法在应用内更新', action: '检查更新' },
  checking: { title: '正在检查更新…', action: '正在检查…' },
  available: { title: '有新版本可用', action: '下载更新', method: 'downloadUpdate' },
  'up-to-date': { title: '已是最新版本', action: '重新检查', method: 'checkForUpdates' },
  downloading: { title: '正在下载更新…', action: '正在下载…' },
  downloaded: { title: '更新已下载', action: '重启并安装', method: 'installUpdate' },
  installing: { title: '正在准备安装…', action: '正在安装…' },
  error: { title: '检查更新失败', action: '重试', method: 'checkForUpdates' }
};

function renderUpdate() {
  const { status, currentVersion, availableVersion, message } = updateState;
  const labels = updateLabels[status] || updateLabels.error;
  const ready = status === 'available' || status === 'downloading' || status === 'downloaded';
  byId('update-indicator').classList.toggle('active', ready);
  byId('update-trigger-label').textContent = ready ? '软件更新' : '检查更新';
  byId('current-version').textContent = currentVersion ? `当前版本 v${currentVersion}` : '当前版本未知';
  byId('update-status').textContent = availableVersion && ready
    ? `${labels.title} · v${availableVersion}`
    : labels.title;
  byId('update-message').textContent = message || (status === 'downloaded' ? '请先保存需要保留的文本，安装时应用将重启。' : '');
  byId('update-message').hidden = !byId('update-message').textContent;

  const downloading = status === 'downloading';
  const percent = Number.isFinite(updateState.progress) ? Math.round(updateState.progress) : null;
  byId('update-progress').hidden = !downloading;
  if (percent === null) progress.removeAttribute('value');
  else progress.value = percent;
  byId('progress-value').textContent = percent === null ? '' : `${percent}%`;
  updateAction.textContent = updatePending && status === 'idle' ? '正在检查…' : labels.action;
  updateAction.disabled = updatePending || !labels.method;
}

async function performUpdateAction() {
  if (updatePending) return;
  const method = updateLabels[updateState.status]?.method;
  if (!method) return;
  updatePending = true;
  renderUpdate();
  try {
    if (!api) throw new Error('无法连接到应用。');
    const revision = updateRevision;
    const nextState = await api[method]();
    if (revision === updateRevision) updateState = nextState;
  } catch {
    updateState = {
      ...updateState,
      status: method === 'checkForUpdates' ? 'error' : method === 'downloadUpdate' ? 'available' : 'downloaded',
      message: '更新操作失败，请重试。'
    };
  } finally {
    updatePending = false;
    renderUpdate();
  }
}

async function initializeUpdates() {
  try {
    if (!api) throw new Error('无法连接到应用。');
    api.onUpdateState((state) => {
      updateRevision += 1;
      updateState = state;
      renderUpdate();
    });
    const revision = updateRevision;
    const state = await api.getUpdateState();
    if (revision === updateRevision) updateState = state;
  } catch {
    updateState = { ...updateState, status: 'unsupported', message: '无法获取应用更新状态。' };
  }
  renderUpdate();
}

byId('open-update').addEventListener('click', () => {
  updateDialog.showModal();
  if (updateState.status === 'idle' || updateState.status === 'up-to-date') performUpdateAction();
});
byId('close-update').addEventListener('click', () => updateDialog.close());
updateAction.addEventListener('click', performUpdateAction);
document.addEventListener('keydown', (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === 'Enter' && !event.isComposing && !updateDialog.open) {
    event.preventDefault();
    form.requestSubmit();
  }
});

renderFields();
initializeUpdates();
