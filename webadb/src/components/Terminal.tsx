import { useState, useRef, useEffect, useCallback } from 'react';
import { adbManager } from '../adb/AdbManager';

function Terminal() {
  const [history, setHistory] = useState<string[]>([]);
  const [currentInput, setCurrentInput] = useState('');
  const [isExecuting, setIsExecuting] = useState(false);
  const [commandHistory, setCommandHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const outputRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [history]);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const executeCommand = useCallback(async (command: string) => {
    if (!command.trim()) return;

    setHistory(prev => [...prev, `$ ${command}`]);
    setCommandHistory(prev => [...prev, command]);
    setHistoryIndex(-1);
    setIsExecuting(true);

    try {
      const output = await adbManager.shell(command);
      if (output.trim()) {
        setHistory(prev => [...prev, output]);
      }
    } catch (error: any) {
      setHistory(prev => [...prev, `错误: ${error.message}`]);
    } finally {
      setIsExecuting(false);
      setCurrentInput('');
    }
  }, []);

  const handleKeyDown = useCallback((e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !isExecuting) {
      executeCommand(currentInput);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (commandHistory.length > 0) {
        const newIndex = historyIndex < commandHistory.length - 1
          ? historyIndex + 1
          : historyIndex;
        setHistoryIndex(newIndex);
        setCurrentInput(commandHistory[commandHistory.length - 1 - newIndex]);
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIndex > 0) {
        const newIndex = historyIndex - 1;
        setHistoryIndex(newIndex);
        setCurrentInput(commandHistory[commandHistory.length - 1 - newIndex]);
      } else if (historyIndex === 0) {
        setHistoryIndex(-1);
        setCurrentInput('');
      }
    } else if (e.key === 'l' && e.ctrlKey) {
      e.preventDefault();
      setHistory([]);
    }
  }, [currentInput, isExecuting, commandHistory, historyIndex, executeCommand]);

  const quickCommands = [
    { label: 'ls', cmd: 'ls /sdcard/' },
    { label: 'pwd', cmd: 'pwd' },
    { label: 'df', cmd: 'df -h' },
    { label: 'top', cmd: 'top -n 1' },
    { label: 'logcat', cmd: 'logcat -d -t 50' },
    { label: 'ps', cmd: 'ps -A' },
    { label: 'getprop', cmd: 'getprop ro.product.model' },
    { label: '电池', cmd: 'dumpsys battery' },
  ];

  return (
    <div className="terminal">
      <div className="terminal-header">
        <span className="terminal-title">Shell 终端</span>
        <div className="terminal-actions">
          <button
            className="btn btn-small"
            onClick={() => setHistory([])}
          >
            清屏
          </button>
        </div>
      </div>

      <div className="quick-commands">
        {quickCommands.map((qc, i) => (
          <button
            key={i}
            className="quick-cmd"
            onClick={() => executeCommand(qc.cmd)}
            disabled={isExecuting}
          >
            {qc.label}
          </button>
        ))}
      </div>

      <div className="terminal-output" ref={outputRef}>
        {history.map((line, i) => (
          <div
            key={i}
            className={`terminal-line ${line.startsWith('$ ') ? 'command' : 'output'}`}
          >
            {line}
          </div>
        ))}
        {isExecuting && (
          <div className="terminal-line executing">
            <span className="spinner small" />
            执行中...
          </div>
        )}
      </div>

      <div className="terminal-input-wrapper">
        <span className="prompt">$</span>
        <input
          ref={inputRef}
          type="text"
          className="terminal-input"
          value={currentInput}
          onChange={(e) => setCurrentInput(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={isExecuting}
          placeholder="输入命令..."
          autoComplete="off"
          spellCheck={false}
        />
      </div>
    </div>
  );
}

export default Terminal;
