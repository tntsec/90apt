document.addEventListener('DOMContentLoaded', () => {
    const fileInput = document.getElementById('fileInput');
    const fileLabel = document.getElementById('fileLabel');
    const fileName = document.getElementById('fileName');
    const btnDecrypt = document.getElementById('btn-decrypt');
    const btnEncrypt = document.getElementById('btn-encrypt');
    const keyInput = document.getElementById('keyInput');
    const ivInput = document.getElementById('ivInput');
    const prefixInput = document.getElementById('prefixInput');
    const editorContainer = document.getElementById('editorContainer');
    const editorContent = document.getElementById('editorContent');
    const btnEditorFormat = document.getElementById('btn-editor-format');
    const btnEditorDownload = document.getElementById('btn-editor-download');
    const btnEditorCancel = document.getElementById('btn-editor-cancel');
    const editorTitle = document.getElementById('editorTitle');
    const fileTypeTip = document.getElementById('fileTypeTip');
    const statusMessage = document.getElementById('statusMessage');
    const presetInfo = document.getElementById('presetInfo');

    let selectedFile = null;
    let editorMode = null;
    let editorOriginalData = null;

    const PRESET_INFO = {
        '7.5': { key: 'Jbga21autoj7ZAsF', iv: 'Jbga21autoj7ZAsF', prefix: '1234567812345678' },
        '8.1': { key: 'Yqwr31autou4PbNM', iv: '1234567812345678', prefix: '9zxc46abc7o28l4t' },
        '8.5': { key: 'Yqwr31autou4PbNM', iv: '1234567812345678', prefix: '9zxc46abc7o28l4t' },
        '9.1': { key: 'Yqwr31autou4PbNM', iv: '1234567812345678', prefix: '9zxc46abc7o28l4t' },
        '9.5': { key: 'Yqwr31autou4PbNM', iv: '1234567812345678', prefix: '9zxc46abc7o28l4t' }
    };

    // Version radio change handler
    document.querySelectorAll('input[name="preset_mode"]').forEach(radio => {
        radio.addEventListener('change', function () {
            const isCustom = this.value === 'custom';
            const customInputs = document.querySelectorAll('.custom-input-group');

            customInputs.forEach(el => {
                el.style.display = isCustom ? 'block' : 'none';
            });

            keyInput.disabled = !isCustom;
            ivInput.disabled = !isCustom;
            prefixInput.disabled = !isCustom;

            if (!isCustom) {
                keyInput.value = '';
                ivInput.value = '';
                prefixInput.value = '';
                updatePresetInfo(this.value);
            } else {
                presetInfo.style.display = 'none';
            }
        });
    });

    function updatePresetInfo(version) {
        const info = PRESET_INFO[version];
        if (info && presetInfo) {
            presetInfo.innerHTML = '<strong>当前预设密钥：</strong> KEY=' + info.key + ' | IV=' + info.iv + ' | Prefix=' + info.prefix;
            presetInfo.style.display = 'block';
        }
    }

    // Initialize preset info for default selection
    const defaultRadio = document.querySelector('input[name="preset_mode"]:checked');
    if (defaultRadio) {
        updatePresetInfo(defaultRadio.value);
    }

    // File input change handler
    fileInput.addEventListener('change', function (e) {
        const file = e.target.files.length ? e.target.files[0] : null;
        selectedFile = file;
        const fname = file ? file.name : '';
        fileName.textContent = fname;

        btnEncrypt.classList.remove('active');
        btnDecrypt.classList.remove('active');
        editorContainer.style.display = 'none';
        fileTypeTip.style.display = 'none';

        if (!file) return;

        if (!/\.(dat|txt|json)$/i.test(fname)) {
            showStatus('请上传 .dat、.txt 或 .json 文件', 'error');
            resetFileInput();
            return;
        }

        if (fname.endsWith('.dat')) {
            btnDecrypt.classList.add('active');
            updateTip('上传 FuncConfig.dat，解密为可编辑内容。');
        } else if (fname.endsWith('.txt')) {
            btnEncrypt.classList.add('active');
            updateTip('上传明文 txt，加密为 .dat 文件。');
        } else if (fname.endsWith('.json')) {
            btnEncrypt.classList.add('active');
            btnDecrypt.classList.add('active');
            updateTip('JSON 文件：可加密为 .dat 或解密为明文 JSON。');
        }
    });

    // Decrypt button
    btnDecrypt.addEventListener('click', async () => {
        if (!selectedFile) { showStatus('请先选择文件', 'error'); return; }

        const config = getSelectedConfig();
        if (!config) return;

        setButtonsDisabled(true);
        try {
            const fileData = new Uint8Array(await selectedFile.arrayBuffer());
            const decryptedText = FuncConfigCrypto.decryptToJSON(fileData, config.key, config.iv);

            openEditor('decrypt', decryptedText, selectedFile.name);
            showStatus('解密成功！可在编辑器中修改后保存。', 'success');
        } catch (err) {
            showStatus('解密失败：' + err.message, 'error');
        } finally {
            setButtonsDisabled(false);
        }
    });

    // Encrypt button
    btnEncrypt.addEventListener('click', async () => {
        if (!selectedFile) { showStatus('请先选择文件', 'error'); return; }

        const config = getSelectedConfig();
        if (!config) return;

        setButtonsDisabled(true);
        try {
            let content;
            const ext = selectedFile.name.split('.').pop().toLowerCase();

            if (ext === 'dat') {
                const fileData = new Uint8Array(await selectedFile.arrayBuffer());
                const decryptedText = FuncConfigCrypto.decryptToJSON(fileData, config.key, config.iv);
                openEditor('encrypt', decryptedText, selectedFile.name);
                setButtonsDisabled(false);
                return;
            } else {
                content = await selectedFile.text();
            }

            let jsonContent = content;
            try {
                JSON.parse(content);
                jsonContent = content;
            } catch (e) {
                if (ext === 'json') {
                    throw new Error('JSON 格式不正确');
                }
            }

            const encrypted = FuncConfigCrypto.encryptFromJSON(jsonContent, config.key, config.iv, config.prefix);
            const baseName = selectedFile.name.replace(/\.[^/.]+$/, '');
            downloadFile(encrypted, baseName + '.dat');
            showStatus('加密成功！', 'success');
        } catch (err) {
            showStatus('加密失败：' + err.message, 'error');
        } finally {
            setButtonsDisabled(false);
        }
    });

    // Editor format button
    btnEditorFormat.addEventListener('click', () => {
        const text = editorContent.value;
        try {
            const jsonFormatted = formatJSON(text);
            editorContent.value = jsonFormatted;
            showStatus('JSON 已格式化', 'success');
        } catch (err) {
            showStatus('格式化失败：' + err.message, 'error');
        }
    });

    // Editor download button
    btnEditorDownload.addEventListener('click', () => {
        const config = getSelectedConfig();
        if (!config) return;

        const text = editorContent.value;

        try {
            JSON.parse(text);
            const encrypted = FuncConfigCrypto.encryptFromJSON(text, config.key, config.iv, config.prefix);
            const baseName = editorOriginalData ? editorOriginalData.replace(/\.[^/.]+$/, '') : 'FuncConfig';
            downloadFile(encrypted, baseName + '.dat');
            showStatus('加密并下载成功！', 'success');
        } catch (err) {
            if (err.message.includes('JSON')) {
                showStatus('JSON 格式不正确，请检查', 'error');
            } else {
                showStatus('加密失败：' + err.message, 'error');
            }
        }
    });

    // Editor cancel button
    btnEditorCancel.addEventListener('click', () => {
        closeEditor();
    });

    function openEditor(mode, content, fileName) {
        editorMode = mode;
        editorOriginalData = fileName;
        editorContent.value = content;
        editorContainer.style.display = 'block';

        if (mode === 'decrypt') {
            editorTitle.textContent = '解密结果 - 可编辑 JSON';
        } else {
            editorTitle.textContent = '编辑并加密 - ' + fileName;
        }

        editorContainer.scrollIntoView({ behavior: 'smooth' });
    }

    function closeEditor() {
        editorContainer.style.display = 'none';
        editorMode = null;
        editorOriginalData = null;
        editorContent.value = '';
    }

    function formatJSON(text) {
        try {
            const obj = JSON.parse(text);
            return JSON.stringify(obj, null, 2);
        } catch (e) {
            return text;
        }
    }

    function getSelectedConfig() {
        const mode = document.querySelector('input[name="preset_mode"]:checked').value;

        if (mode === 'custom') {
            const key = keyInput.value;
            const iv = ivInput.value;
            const prefix = prefixInput.value;

            if (key.length !== 16 || iv.length !== 16) {
                showStatus('自定义模式下 KEY 和 IV 必须为 16 字节', 'error');
                return null;
            }

            return { key, iv, prefix: prefix || '1234567812345678' };
        } else {
            const info = PRESET_INFO[mode];
            if (!info) {
                showStatus('未知版本：' + mode, 'error');
                return null;
            }
            return info;
        }
    }

    function setButtonsDisabled(disabled) {
        btnDecrypt.disabled = disabled;
        btnEncrypt.disabled = disabled;
    }

    function resetFileInput() {
        fileInput.value = '';
        fileName.textContent = '';
        selectedFile = null;
        btnEncrypt.classList.remove('active');
        btnDecrypt.classList.remove('active');
    }

    function updateTip(text) {
        fileTypeTip.innerHTML = text;
        fileTypeTip.style.display = 'block';
    }

    function showStatus(msg, type) {
        statusMessage.textContent = msg;
        statusMessage.className = 'status-message status-' + type;
        statusMessage.style.display = 'block';
        clearTimeout(statusMessage._timer);
        statusMessage._timer = setTimeout(() => {
            statusMessage.style.display = 'none';
        }, 5000);
    }

    function downloadFile(data, filename) {
        const blob = new Blob([data], { type: 'application/octet-stream' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        setTimeout(() => {
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        }, 200);
    }

    // Drag and drop support
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        document.addEventListener(eventName, e => { e.preventDefault(); e.stopPropagation(); });
    });

    ['dragenter', 'dragover'].forEach(eventName => {
        document.addEventListener(eventName, () => {
            fileLabel.classList.add('dragover');
        });
    });

    ['dragleave', 'drop'].forEach(eventName => {
        document.addEventListener(eventName, () => {
            fileLabel.classList.remove('dragover');
        });
    });

    document.addEventListener('drop', e => {
        const files = e.dataTransfer.files;
        if (!files || !files.length) return;
        const file = files[0];

        if (!/\.(dat|txt|json)$/i.test(file.name)) {
            showStatus('请上传 .dat、.txt 或 .json 文件', 'error');
            return;
        }

        const dataTransfer = new DataTransfer();
        dataTransfer.items.add(file);
        fileInput.files = dataTransfer.files;
        fileInput.dispatchEvent(new Event('change'));
    });

    // Mobile detection
    function isMobile() {
        return /android|iphone|ipad|ipod|mobile/i.test(navigator.userAgent);
    }
    fileLabel.textContent = isMobile() ? '点击选择 .dat、.txt 或 .json 文件' : '点击或拖拽上传 .dat、.txt 或 .json 文件';
});
