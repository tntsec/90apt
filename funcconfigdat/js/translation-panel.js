/**
 * 翻译对照面板
 *
 * 解密后在编辑器右侧（窄屏时移到下方）列出当前文件里每个键对应的中文翻译。
 * 词库来自 js/translations.js（由 tools/build-translations.py 从两份「自用」txt 生成），
 * 按命中的键数量自动判断当前文件属于 FuncConfig 还是 UiConfig 词库，也可手动切换。
 */
const TranslationPanel = (() => {
    // translations.js 里用的是顶层 const，不会挂到 window 上，必须按标识符引用；
    // typeof 守卫避免词库文件缺失时抛 ReferenceError
    const DICTS = [
        { id: 'func', name: 'FuncConfig', get: () => (typeof FuncConfigTranslations !== 'undefined' ? FuncConfigTranslations : null) },
        { id: 'ui', name: 'UiConfig', get: () => (typeof UiConfigTranslations !== 'undefined' ? UiConfigTranslations : null) }
    ];

    // 抓一行开头的 "键": —— 值里可能含转义，所以用非贪婪的转义感知写法。
    // 缩进与冒号单独分组，方便跳转时只选中 "键" 本身。
    const KEY_LINE_RE = /^(\s*)"((?:[^"\\]|\\.)*)"\s*:/;
    const MAX_ROWS = 2000;

    let el = null;
    let hooks = null;
    let entries = [];          // [{ line, start, end, key }]
    let dictMode = 'auto';     // auto | func | ui
    let activeDict = null;     // 当前实际使用的词库
    let onlyMissing = false;
    let filterText = '';
    let currentLine = -1;
    let renderTimer = null;

    function resolveMaps() {
        return DICTS.map((d) => {
            let map = null;
            try { map = d.get(); } catch (e) { map = null; }
            return { id: d.id, name: d.name, map: map || {} };
        });
    }

    function hasOwn(map, key) {
        return !!map && Object.prototype.hasOwnProperty.call(map, key);
    }

    function escapeHtml(str) {
        return String(str).replace(/[&<>"]/g, (c) => (
            { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]
        ));
    }

    /** 逐行扫出 "键": 的位置与行号，行号用于和编辑器光标联动 */
    function extractKeys(text) {
        const out = [];
        if (!text) return out;
        const lines = text.split('\n');
        let offset = 0;

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const m = KEY_LINE_RE.exec(line);
            if (m) {
                let key = m[2];
                if (key.indexOf('\\') !== -1) {
                    try { key = JSON.parse('"' + key + '"'); } catch (e) { /* 保留原样 */ }
                }
                const start = offset + m[1].length;
                out.push({
                    line: i,
                    start: start,                          // 指向键名开头的引号
                    end: start + m[2].length + 2,          // 覆盖 "键" 两个引号
                    key: key
                });
            }
            offset += line.length + 1;
        }
        return out;
    }

    /** 自动判断词库：按命中键数量取高的那份 */
    function detectDict(maps) {
        let best = maps[0];
        let bestHits = -1;
        for (const item of maps) {
            let hits = 0;
            for (const entry of entries) {
                if (hasOwn(item.map, entry.key)) hits++;
            }
            item.hits = hits;
            if (hits > bestHits) { bestHits = hits; best = item; }
        }
        return best;
    }

    function init(options) {
        hooks = options || {};
        el = {
            panel: document.getElementById('translationPanel'),
            badge: document.getElementById('translationBadge'),
            filter: document.getElementById('translationFilter'),
            list: document.getElementById('translationList'),
            footer: document.getElementById('translationFooter'),
            switchBtns: Array.from(document.querySelectorAll('[data-dict]')),
            onlyMissingBtn: document.getElementById('btn-translation-missing')
        };
        if (!el.panel) return;

        el.filter.addEventListener('input', () => {
            filterText = el.filter.value.trim().toLowerCase();
            renderList();
        });

        el.switchBtns.forEach((btn) => {
            btn.addEventListener('click', () => {
                dictMode = btn.dataset.dict;
                el.switchBtns.forEach((b) => b.classList.toggle('active', b.dataset.dict === dictMode));
                renderList();
            });
        });

        if (el.onlyMissingBtn) {
            el.onlyMissingBtn.addEventListener('click', () => {
                onlyMissing = !onlyMissing;
                el.onlyMissingBtn.classList.toggle('active', onlyMissing);
                renderList();
            });
        }

        // 点某一行 → 在编辑器里选中该键并滚动过去
        el.list.addEventListener('click', (e) => {
            const row = e.target.closest ? e.target.closest('.translation-row') : null;
            if (!row || !hooks.onJump) return;
            const index = Number(row.dataset.index);
            const entry = entries[index];
            if (!entry) return;
            hooks.onJump(entry);
            setCurrentLine(entry.line, true);
        });
    }

    function getDictMaps() {
        return resolveMaps();
    }

    function pickDict(maps) {
        if (dictMode === 'auto') return detectDict(maps);
        return maps.find((m) => m.id === dictMode) || detectDict(maps);
    }

    /** 解析当前内容并重绘整个面板 */
    function render(text) {
        if (!el) return;
        entries = extractKeys(text);
        if (typeof hooks.onEntryCount === 'function') hooks.onEntryCount(entries.length);
        renderList();
    }

    function scheduleRender(text) {
        clearTimeout(renderTimer);
        renderTimer = setTimeout(() => render(text), 200);
    }

    function renderList() {
        if (!el || !el.list) return;

        const maps = getDictMaps();
        const dict = pickDict(maps);
        activeDict = dict;

        const translatedCount = entries.reduce((n, e) => n + (hasOwn(dict.map, e.key) ? 1 : 0), 0);

        // 键数太少时自动判定不可靠，给出提示但仍按最接近的词库显示
        const reliable = dict.hits > 0 && dict.hits >= Math.min(3, entries.length);
        el.badge.textContent = dict.name + (reliable ? '' : '（?）');
        el.badge.classList.toggle('uncertain', !reliable);
        el.badge.title = reliable
            ? `已按命中 ${dict.hits}/${entries.length} 个键自动识别为 ${dict.name} 词库`
            : '命中键过少，词库可能判断不准，可手动切换';

        if (!entries.length) {
            el.list.innerHTML = '<div class="translation-empty">当前内容里没找到 "键": 形式的数据</div>';
            updateFooter(0, 0, 0);
            return;
        }

        const rows = [];
        let shown = 0;
        let missing = 0;

        for (let i = 0; i < entries.length && shown < MAX_ROWS; i++) {
            const entry = entries[i];
            const has = hasOwn(dict.map, entry.key);
            const text = has ? dict.map[entry.key] : '';
            if (!has) missing++;

            if (onlyMissing && has) continue;
            if (filterText) {
                const haystack = (entry.key + ' ' + text).toLowerCase();
                if (haystack.indexOf(filterText) === -1) continue;
            }

            rows.push(
                `<div class="translation-row${has ? '' : ' missing'}" data-index="${i}">` +
                    `<span class="translation-row-line">${entry.line + 1}</span>` +
                    `<span class="translation-row-body">` +
                        `<span class="translation-row-key">${escapeHtml(entry.key)}</span>` +
                        `<span class="translation-row-text">${has ? escapeHtml(text) : '未收录'}</span>` +
                    '</span>' +
                '</div>'
            );
            shown++;
        }

        if (!rows.length) {
            el.list.innerHTML = '<div class="translation-empty">' +
                (onlyMissing ? '所有键都已有翻译' : '没有匹配的条目') + '</div>';
        } else {
            el.list.innerHTML = rows.join('');
            if (entries.length > MAX_ROWS) {
                el.list.insertAdjacentHTML('beforeend',
                    `<div class="translation-more">仅列出前 ${MAX_ROWS} 条</div>`);
            }
            setCurrentLine(currentLine, true);
        }

        updateFooter(entries.length, translatedCount, missing);
    }

    function updateFooter(total, translated, missing) {
        if (!el.footer) return;
        if (!total) { el.footer.textContent = ''; return; }
        const pct = Math.round((translated / total) * 100);
        el.footer.innerHTML =
            `<span>共 <b>${total}</b> 个键 · 已翻译 <b class="ok">${translated}</b>` +
            ` · 未收录 <b class="${missing ? 'warn' : ''}">${missing}</b>（${pct}%）</span>`;
    }

    /** 高亮编辑器光标所在行对应的条目，scroll 为 true 时把它滚进可视区 */
    function setCurrentLine(line, scroll) {
        if (!el || !el.list) return;
        currentLine = line;

        let targetIndex = -1;
        for (let i = 0; i < entries.length; i++) {
            if (entries[i].line === line) { targetIndex = i; break; }
        }

        const rows = el.list.querySelectorAll('.translation-row');
        let hit = null;
        for (const row of rows) {
            const isCurrent = targetIndex !== -1 && Number(row.dataset.index) === targetIndex;
            row.classList.toggle('current', isCurrent);
            if (isCurrent) hit = row;
        }

        if (hit && scroll) {
            const top = hit.offsetTop - el.list.offsetTop;
            if (top < el.list.scrollTop || top + hit.offsetHeight > el.list.scrollTop + el.list.clientHeight) {
                el.list.scrollTop = top - el.list.clientHeight / 3;
            }
        }
    }

    function setDictMode(mode) {
        dictMode = mode;
        if (el && el.switchBtns) {
            el.switchBtns.forEach((b) => b.classList.toggle('active', b.dataset.dict === dictMode));
        }
    }

    function reset() {
        clearTimeout(renderTimer);
        entries = [];
        filterText = '';
        onlyMissing = false;
        currentLine = -1;
        if (el) {
            if (el.filter) el.filter.value = '';
            if (el.list) el.list.innerHTML = '';
            if (el.footer) el.footer.textContent = '';
            if (el.badge) { el.badge.textContent = '—'; el.badge.classList.remove('uncertain'); }
            if (el.onlyMissingBtn) el.onlyMissingBtn.classList.remove('active');
        }
        setDictMode('auto');
    }

    return {
        init,
        render,
        scheduleRender,
        reset,
        setCurrentLine,
        setDictMode,
        getActiveDictName: () => (activeDict ? activeDict.name : '')
    };
})();
