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
    const editorSearch = document.getElementById('editorSearch');
    const editorSearchInput = document.getElementById('editorSearchInput');
    const editorSearchCount = document.getElementById('editorSearchCount');
    const editorSearchResults = document.getElementById('editorSearchResults');
    const btnEditorSearch = document.getElementById('btn-editor-search');
    const btnSearchPrev = document.getElementById('btn-search-prev');
    const btnSearchNext = document.getElementById('btn-search-next');
    const btnSearchCase = document.getElementById('btn-search-case');
    const btnSearchRegex = document.getElementById('btn-search-regex');
    const btnSearchClose = document.getElementById('btn-search-close');
    const fileTypeTip = document.getElementById('fileTypeTip');
    const statusMessage = document.getElementById('statusMessage');
    const presetInfo = document.getElementById('presetInfo');
    const pageContainer = document.getElementById('pageContainer');

    let selectedFile = null;
    let editorMode = null;
    let editorOriginalData = null;
    // 打开编辑器时锁定的密钥配置，避免中途切换版本导致「用 A 版解密、用 B 版加密」
    let editorConfig = null;

    // 加解密库可用性检查：本地加载失败时给出明确提示，而不是加密时报 undefined。
    // 注意 CryptoJS.AES 是对象而非函数，这里要校验其 encrypt/decrypt 方法。
    if (typeof CryptoJS === 'undefined' || !CryptoJS.AES || typeof CryptoJS.AES.encrypt !== 'function') {
        showStatus('加解密库加载失败，请确认 js/vendor/crypto-js.min.js 文件存在', 'error');
        btnDecrypt.disabled = true;
        btnEncrypt.disabled = true;
        return;
    }

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
                showStatus('自定义模式：KEY、IV、Prefix 三项均需填满 16 字节（注意中文一字占 3 字节）', 'warning');
            }
        });
    });

    function formatPrefixDisplay(prefix) {
        const bytes = new TextEncoder().encode(prefix);
        const hasBinary = Array.from(bytes).some((b) => b < 32 || b > 126);
        if (!hasBinary) {
            return prefix;
        }
        return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
    }

    function updatePresetInfo(version) {
        const info = FuncConfigCrypto.getPreset(version);
        if (info && presetInfo) {
            presetInfo.innerHTML = '<strong>当前预设密钥：</strong> KEY=' + info.key + ' | IV=' + info.iv + ' | Prefix=' + formatPrefixDisplay(info.prefix);
            presetInfo.style.display = 'block';
        }
    }

    // Initialize preset info for default selection
    const defaultRadio = document.querySelector('input[name="preset_mode"]:checked');
    if (defaultRadio) {
        updatePresetInfo(defaultRadio.value);
    }

    function getExtension(name) {
        const idx = name.lastIndexOf('.');
        return idx === -1 ? '' : name.slice(idx + 1).toLowerCase();
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
        if (pageContainer) pageContainer.classList.remove('wide');
        if (typeof TranslationPanel !== 'undefined') TranslationPanel.reset();
        fileTypeTip.style.display = 'none';

        if (!file) return;

        if (!/\.(dat|txt|json)$/i.test(fname)) {
            showStatus('请上传 .dat、.txt 或 .json 文件', 'error');
            resetFileInput();
            return;
        }

        const ext = getExtension(fname);

        if (ext === 'dat') {
            btnDecrypt.classList.add('active');
            btnEncrypt.classList.add('active');
            updateTip('上传 FuncConfig.dat：点「解密文件」查看内容，或点「加密文件」编辑后重新加密。');
        } else if (ext === 'txt') {
            btnEncrypt.classList.add('active');
            updateTip('上传明文 txt，加密为 .dat 文件（按 UTF-8 读取）。');
        } else if (ext === 'json') {
            btnEncrypt.classList.add('active');
            updateTip('上传明文 JSON，加密为 .dat 文件。');
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

            openEditor('decrypt', decryptedText, selectedFile.name, config);
            showStatus('解密成功！右侧已显示中文对照，可在编辑器中修改后保存。', 'success');
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
            const ext = getExtension(selectedFile.name);

            // .dat 走「先解密再进入编辑器」的重新加密流程
            if (ext === 'dat') {
                const fileData = new Uint8Array(await selectedFile.arrayBuffer());
                const decryptedText = FuncConfigCrypto.decryptToJSON(fileData, config.key, config.iv);
                openEditor('encrypt', decryptedText, selectedFile.name, config);
                showStatus('已解密，可在编辑器中修改后保存。', 'success');
                return;
            }

            const content = await selectedFile.text();

            if (ext === 'json') {
                try {
                    JSON.parse(content);
                } catch (e) {
                    throw new Error('JSON 格式不正确');
                }
            }

            const encrypted = FuncConfigCrypto.encryptFromJSON(content, config.key, config.iv, config.prefix);
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
        if (!text.trim()) { showStatus('内容为空', 'error'); return; }
        try {
            editorContent.value = JSON.stringify(JSON.parse(text), null, 2);
            showStatus('JSON 已格式化', 'success');
            // 格式化改变了缩进与行号，匹配结果需要重算（不跳转，避免打断阅读）
            if (editorSearch.classList.contains('open') && editorSearchInput.value) {
                clearTimeout(searchTimer);
                runSearch(true, false);
            }
        } catch (err) {
            showStatus('格式化失败：内容不是合法 JSON', 'error');
        }
    });

    // Editor download button
    btnEditorDownload.addEventListener('click', () => {
        const config = editorConfig || getSelectedConfig();
        if (!config) return;

        const text = editorContent.value;
        if (!text.trim()) { showStatus('内容为空，无法加密', 'error'); return; }

        // 以 { 或 [ 开头的疑似 JSON 若解析失败，说明是写错了，直接拦下；
        // 其余纯文本（含解密出来的非 JSON 内容）允许原样加密，避免解密后无法保存。
        let warning = '';
        try {
            JSON.parse(text);
        } catch (e) {
            if (/^\s*[\[{]/.test(text)) {
                showStatus('JSON 格式不正确，请检查后再保存', 'error');
                return;
            }
            warning = '（内容非 JSON，已按纯文本加密）';
        }

        try {
            const encrypted = FuncConfigCrypto.encryptFromJSON(text, config.key, config.iv, config.prefix);
            const baseName = editorOriginalData ? editorOriginalData.replace(/\.[^/.]+$/, '') : 'FuncConfig';
            downloadFile(encrypted, baseName + '.dat');
            showStatus('加密并下载成功！' + warning, 'success');
        } catch (err) {
            showStatus('加密失败：' + err.message, 'error');
        }
    });

    // Editor cancel button
    btnEditorCancel.addEventListener('click', () => {
        closeEditor();
    });

    /* ============================================================
       编辑器搜索
       在 textarea 里无法做真正的语法高亮，所以采用「选中 + 定位 + 结果列表」
       的组合：回车逐个跳转，结果列表给出所在行与上下文，点列表项直接进入编辑。
       ============================================================ */

    const MAX_MATCHES = 5000;      // 上限，避免超大文件 + 宽泛正则把页面卡死
    const MAX_RESULT_ROWS = 300;   // 结果列表最多渲染多少行

    let searchMatches = [];
    let searchIndex = -1;
    let searchAppliedQuery = null; // 已应用到当前匹配结果的查询串
    let searchInvalid = false;     // 上一次搜索是否因为正则不合法而失败
    let searchCaseSensitive = false;
    let searchUseRegex = false;
    let searchTimer = null;

    function escapeRegExp(str) {
        return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    // 预先记录每个换行符的位置，用二分查找把「字符下标」换算成「行号」
    function buildNewlineIndex(text) {
        const newlines = [];
        for (let i = 0; i < text.length; i++) {
            if (text.charCodeAt(i) === 10) newlines.push(i);
        }
        return newlines;
    }

    function locateIndex(newlines, index) {
        // 返回 0 基的行号，以及该行的起止下标
        let lo = 0;
        let hi = newlines.length;
        while (lo < hi) {
            const mid = (lo + hi) >> 1;
            if (newlines[mid] < index) lo = mid + 1;
            else hi = mid;
        }
        return {
            line: lo,                                                    // 0 基
            lineStart: lo === 0 ? 0 : newlines[lo - 1] + 1,
            lineEnd: lo < newlines.length ? newlines[lo] : Infinity      // 无换行时截到文末
        };
    }

    function collectMatches(text, query) {
        let re;
        try {
            re = new RegExp(
                searchUseRegex ? query : escapeRegExp(query),
                'g' + (searchCaseSensitive ? '' : 'i') + (searchUseRegex ? 'm' : '')
            );
        } catch (err) {
            return { matches: [], invalid: true };
        }

        const newlines = buildNewlineIndex(text);
        const matches = [];
        let m;
        while ((m = re.exec(text)) !== null) {
            const where = locateIndex(newlines, m.index);
            matches.push({
                start: m.index,
                end: m.index + m[0].length,
                line: where.line,
                lineStart: where.lineStart,
                lineEnd: where.lineEnd
            });
            if (m[0].length === 0) re.lastIndex++;         // 零宽匹配，手动前进防止死循环
            if (matches.length >= MAX_MATCHES) break;
        }
        return { matches, invalid: false };
    }

    function updateSearchCount() {
        if (!editorSearchInput.value) {
            editorSearchCount.textContent = '';
            editorSearchCount.classList.remove('no-match');
            return;
        }
        if (searchInvalid) {
            editorSearchCount.textContent = '语法错误';
            editorSearchCount.classList.add('no-match');
            return;
        }
        if (!searchMatches.length) {
            editorSearchCount.textContent = '无匹配';
            editorSearchCount.classList.add('no-match');
            return;
        }
        editorSearchCount.classList.remove('no-match');
        editorSearchCount.textContent = (searchIndex + 1) + '/' + searchMatches.length;
    }

    // 把 textarea 滚动到指定行（1/3 高度处），不依赖 focus 的自动滚动
    function scrollEditorToLine(line) {
        const style = window.getComputedStyle(editorContent);
        const fontSize = parseFloat(style.fontSize) || 14;
        let lineHeight = parseFloat(style.lineHeight);
        if (!lineHeight || Number.isNaN(lineHeight)) lineHeight = fontSize * 1.5;
        else if (lineHeight < 4) lineHeight *= fontSize;   // line-height 为无单位倍数时

        const paddingTop = parseFloat(style.paddingTop) || 0;
        const target = line * lineHeight + paddingTop - (editorContent.clientHeight / 3);
        editorContent.scrollTop = Math.max(0, target);
    }

    function renderSearchResults() {
        const query = editorSearchInput.value;
        editorSearchResults.innerHTML = '';

        if (!query) {
            editorSearchResults.classList.remove('open');
            return;
        }

        editorSearchResults.classList.add('open');

        if (!searchMatches.length) {
            const empty = document.createElement('div');
            empty.className = 'editor-search-empty';
            empty.textContent = searchInvalid ? '正则表达式不合法' : '没有找到匹配内容';
            editorSearchResults.appendChild(empty);
            return;
        }

        const text = editorContent.value;
        const rows = Math.min(searchMatches.length, MAX_RESULT_ROWS);

        for (let i = 0; i < rows; i++) {
            const match = searchMatches[i];
            const lineEnd = Math.min(match.lineEnd, text.length);
            const lineText = text.slice(match.lineStart, lineEnd);
            const relStart = match.start - match.lineStart;
            const relEnd = Math.min(match.end, lineEnd) - match.lineStart;

            const row = document.createElement('div');
            row.className = 'search-result' + (i === searchIndex ? ' current' : '');
            row.dataset.index = String(i);
            row.title = lineText.trim();

            const num = document.createElement('span');
            num.className = 'search-result-line';
            num.textContent = String(match.line + 1);

            const body = document.createElement('span');
            body.className = 'search-result-text';

            const from = Math.max(0, relStart - 32);
            const to = Math.min(lineText.length, relEnd + 32);
            if (from > 0) body.appendChild(document.createTextNode('…'));
            body.appendChild(document.createTextNode(lineText.slice(from, relStart)));

            const mark = document.createElement('span');
            mark.className = 'search-result-mark';
            mark.textContent = lineText.slice(relStart, relEnd);
            body.appendChild(mark);

            body.appendChild(document.createTextNode(lineText.slice(relEnd, to)));
            if (to < lineText.length) body.appendChild(document.createTextNode('…'));

            row.appendChild(num);
            row.appendChild(body);
            editorSearchResults.appendChild(row);
        }

        if (searchMatches.length > rows) {
            const more = document.createElement('div');
            more.className = 'search-result-more';
            more.textContent = '仅列出前 ' + rows + ' 条，共 ' + searchMatches.length + ' 条匹配（回车可逐个跳转）';
            editorSearchResults.appendChild(more);
        }
    }

    function markCurrentResult() {
        const rows = editorSearchResults.querySelectorAll('.search-result');
        for (let i = 0; i < rows.length; i++) {
            rows[i].classList.toggle('current', i === searchIndex);
        }

        const current = editorSearchResults.querySelector('.search-result.current');
        if (!current) return;
        // 让当前项在结果列表内保持可见（不触发整页滚动）
        const offset = current.offsetTop - editorSearchResults.offsetTop;
        if (offset < editorSearchResults.scrollTop) {
            editorSearchResults.scrollTop = offset;
        } else if (offset + current.offsetHeight >
                   editorSearchResults.scrollTop + editorSearchResults.clientHeight) {
            editorSearchResults.scrollTop = offset + current.offsetHeight - editorSearchResults.clientHeight;
        }
    }

    // focusEditor 为 true 时把光标交给 textarea，便于直接修改；否则保持在搜索框里连续回车跳转
    function goToMatch(target, focusEditor) {
        if (!searchMatches.length) {
            searchIndex = -1;
            updateSearchCount();
            return;
        }

        const total = searchMatches.length;
        searchIndex = ((target % total) + total) % total;

        const match = searchMatches[searchIndex];
        editorContent.setSelectionRange(match.start, match.end);
        scrollEditorToLine(match.line);
        if (focusEditor) editorContent.focus();

        updateSearchCount();
        markCurrentResult();
    }

    function runSearch(resetIndex, jump) {
        const query = editorSearchInput.value;

        if (!query) {
            searchMatches = [];
            searchIndex = -1;
            searchAppliedQuery = null;
            searchInvalid = false;
            editorSearchInput.classList.remove('invalid');
            updateSearchCount();
            renderSearchResults();
            return;
        }

        const result = collectMatches(editorContent.value, query);
        searchInvalid = result.invalid;
        editorSearchInput.classList.toggle('invalid', result.invalid);
        searchAppliedQuery = result.invalid ? null : query;
        searchMatches = result.matches;

        if (resetIndex || searchIndex < 0) searchIndex = 0;
        if (searchIndex >= searchMatches.length) searchIndex = searchMatches.length - 1;

        const jumpTarget = searchIndex < 0 ? 0 : searchIndex;
        renderSearchResults();

        if (jump && searchMatches.length) {
            goToMatch(jumpTarget, false);
        } else {
            if (!searchMatches.length) searchIndex = -1;
            updateSearchCount();
            markCurrentResult();
        }
    }

    function scheduleSearch(delay) {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => runSearch(false, false), delay);
    }

    function toggleSearch(open) {
        const willOpen = typeof open === 'boolean' ? open : !editorSearch.classList.contains('open');
        editorSearch.classList.toggle('open', willOpen);
        btnEditorSearch.classList.toggle('active', willOpen);

        if (willOpen) {
            editorSearchInput.focus();
            editorSearchInput.select();
            if (editorSearchInput.value) runSearch(true, true);
            return;
        }

        clearTimeout(searchTimer);
        searchMatches = [];
        searchIndex = -1;
        searchAppliedQuery = null;
        searchInvalid = false;
        editorSearchResults.innerHTML = '';
        editorSearchResults.classList.remove('open');
        if (editorContainer.style.display !== 'none') editorContent.focus();
    }

    function resetSearch() {
        clearTimeout(searchTimer);
        editorSearchInput.value = '';
        editorSearchInput.classList.remove('invalid');
        editorSearchCount.textContent = '';
        editorSearchCount.classList.remove('no-match');
        editorSearchResults.innerHTML = '';
        editorSearchResults.classList.remove('open');
        editorSearch.classList.remove('open');
        btnEditorSearch.classList.remove('active');
        searchMatches = [];
        searchIndex = -1;
        searchAppliedQuery = null;
        searchInvalid = false;
        searchCaseSensitive = false;
        searchUseRegex = false;
        btnSearchCase.classList.remove('active');
        btnSearchRegex.classList.remove('active');
    }

    btnEditorSearch.addEventListener('click', () => toggleSearch());
    btnSearchClose.addEventListener('click', () => toggleSearch(false));

    btnSearchPrev.addEventListener('click', () => {
        editorSearchInput.focus();
        goToMatch(searchIndex - 1, false);
    });

    btnSearchNext.addEventListener('click', () => {
        editorSearchInput.focus();
        goToMatch(searchIndex + 1, false);
    });

    btnSearchCase.addEventListener('click', () => {
        searchCaseSensitive = !searchCaseSensitive;
        btnSearchCase.classList.toggle('active', searchCaseSensitive);
        editorSearchInput.focus();
        runSearch(true, true);
    });

    btnSearchRegex.addEventListener('click', () => {
        searchUseRegex = !searchUseRegex;
        btnSearchRegex.classList.toggle('active', searchUseRegex);
        editorSearchInput.focus();
        runSearch(true, true);
    });

    editorSearchInput.addEventListener('input', () => {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => runSearch(true, true), 120);
    });

    editorSearchInput.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter') return;
        e.preventDefault();
        // 防抖还没触发时先按最新查询算一次，避免跳到上一次的结果
        if (editorSearchInput.value !== searchAppliedQuery) {
            clearTimeout(searchTimer);
            runSearch(true, true);
            return;
        }
        goToMatch(searchIndex + (e.shiftKey ? -1 : 1), false);
    });

    editorSearchResults.addEventListener('click', (e) => {
        const row = e.target && e.target.closest ? e.target.closest('.search-result') : null;
        if (!row) return;
        goToMatch(Number(row.dataset.index), true);
    });

    // 编辑内容后只刷新匹配与列表，不动光标、不滚动，避免打断正在进行的编辑
    editorContent.addEventListener('input', () => {
        if (editorSearch.classList.contains('open') && editorSearchInput.value) {
            scheduleSearch(200);
        }
        // 增删键之后翻译对照需要跟着更新（内部已做防抖）
        if (typeof TranslationPanel !== 'undefined') {
            TranslationPanel.scheduleRender(editorContent.value);
        }
    });

    // Ctrl/Cmd+F 打开搜索；Esc 关闭搜索。编辑器未打开时不拦截浏览器原生查找
    document.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && (e.key === 'f' || e.key === 'F')) {
            if (editorContainer.style.display === 'none') return;
            e.preventDefault();
            toggleSearch(true);
        } else if (e.key === 'Escape' && editorSearch.classList.contains('open')) {
            e.preventDefault();
            toggleSearch(false);
        }
    });

    /* ============================================================
       翻译对照面板
       解密后在编辑器外侧列出当前文件每个键对应的中文翻译。
       词库来自 js/translations.js（1100+ 条），只在打开编辑器 / 内容变化时重建。
       ============================================================ */

    const CURSOR_SYNC_DELAY = 80;
    let cursorSyncTimer = null;

    // 编辑器里大多是缩进 JSON，逐字符数换行比 slice().split() 更省内存
    function lineOfIndex(text, index) {
        let line = 0;
        const end = Math.min(index, text.length);
        for (let i = 0; i < end; i++) {
            if (text.charCodeAt(i) === 10) line++;
        }
        return line;
    }

    function syncPanelToCursor() {
        if (editorContainer.style.display === 'none') return;
        TranslationPanel.setCurrentLine(
            lineOfIndex(editorContent.value, editorContent.selectionStart),
            true
        );
    }

    function scheduleCursorSync() {
        clearTimeout(cursorSyncTimer);
        cursorSyncTimer = setTimeout(syncPanelToCursor, CURSOR_SYNC_DELAY);
    }

    if (typeof TranslationPanel !== 'undefined') {
        TranslationPanel.init({
            // 点翻译列表某一行 → 在编辑器里选中对应的键并滚动过去
            onJump: function (match) {
                editorContent.setSelectionRange(match.start, match.end);
                scrollEditorToLine(match.line);
                editorContent.focus();
            }
        });
    } else {
        // 面板脚本缺失时直接隐藏，不影响加解密主流程
        const panelEl = document.getElementById('translationPanel');
        if (panelEl) panelEl.style.display = 'none';
    }

    editorContent.addEventListener('keyup', scheduleCursorSync);
    editorContent.addEventListener('click', scheduleCursorSync);
    editorContent.addEventListener('select', scheduleCursorSync);

    function openEditor(mode, content, fileName, config) {
        editorMode = mode;
        editorOriginalData = fileName;
        editorConfig = config;
        editorContent.value = content;
        editorContainer.style.display = 'block';
        if (pageContainer) pageContainer.classList.add('wide');
        resetSearch();

        if (typeof TranslationPanel !== 'undefined') TranslationPanel.render(content);

        const suffix = config && config.label ? '（' + config.label + '）' : '';
        editorTitle.textContent = mode === 'decrypt'
            ? '解密结果 - 可编辑 JSON' + suffix
            : '编辑并加密 - ' + fileName + suffix;

        editorContainer.scrollIntoView({ behavior: 'smooth' });
    }

    function closeEditor() {
        resetSearch();
        editorContainer.style.display = 'none';
        if (pageContainer) pageContainer.classList.remove('wide');
        if (typeof TranslationPanel !== 'undefined') TranslationPanel.reset();
        editorMode = null;
        editorOriginalData = null;
        editorConfig = null;
        editorContent.value = '';
    }

    function validateCustomField(input, label) {
        const bytes = FuncConfigCrypto.utf8ByteLength(input.value);
        if (bytes !== 16) {
            showStatus(label + ' 必须为 16 字节（当前 ' + bytes + ' 字节）', 'error');
            input.focus();
            return false;
        }
        return true;
    }

    function getSelectedConfig() {
        const checked = document.querySelector('input[name="preset_mode"]:checked');
        if (!checked) {
            showStatus('请先选择版本', 'error');
            return null;
        }

        const mode = checked.value;

        if (mode === 'custom') {
            if (!validateCustomField(keyInput, 'KEY')) return null;
            if (!validateCustomField(ivInput, 'IV')) return null;
            if (!validateCustomField(prefixInput, '数据填充 Prefix')) return null;
            return { key: keyInput.value, iv: ivInput.value, prefix: prefixInput.value, label: '自定义' };
        }

        const info = FuncConfigCrypto.getPreset(mode);
        if (!info) {
            showStatus('未知版本：' + mode, 'error');
            return null;
        }
        return { key: info.key, iv: info.iv, prefix: info.prefix, label: mode };
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
        fileTypeTip.style.display = 'none';
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
