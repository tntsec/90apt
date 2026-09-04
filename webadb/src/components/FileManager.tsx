import { useState, useCallback, useRef } from 'react';
import { adbManager } from '../adb/AdbManager';

function FileManager() {
  const [currentPath, setCurrentPath] = useState('/sdcard/');
  const [files, setFiles] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const loadFiles = useCallback(async (path: string) => {
    setLoading(true);
    setError('');
    try {
      const output = await adbManager.shell(`ls -1 "${path}"`);
      const fileList = output.split('\n').filter(f => f.trim()).map(f => f.trim());
      setFiles(fileList);
      setCurrentPath(path);
    } catch (err: any) {
      setError(err.message || '加载文件列表失败');
      setFiles([]);
    } finally {
      setLoading(false);
    }
  }, []);

  const handlePushFile = useCallback(async (file: File) => {
    try {
      const data = new Uint8Array(await file.arrayBuffer());
      const remotePath = `${currentPath}${file.name}`;
      await adbManager.pushFile(data, remotePath);
      loadFiles(currentPath);
    } catch (err: any) {
      setError(err.message || '上传文件失败');
    }
  }, [currentPath, loadFiles]);

  const handlePullFile = useCallback(async (fileName: string) => {
    try {
      const remotePath = currentPath.endsWith('/')
        ? `${currentPath}${fileName}`
        : `${currentPath}/${fileName}`;

      const data = await adbManager.pullFile(remotePath);
      const blob = new Blob([data.buffer as ArrayBuffer]);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = fileName;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setError(err.message || '下载文件失败');
    }
  }, [currentPath]);

  const handleDelete = useCallback(async (fileName: string) => {
    if (!confirm(`确定要删除 ${fileName} 吗？`)) return;

    try {
      const remotePath = currentPath.endsWith('/')
        ? `${currentPath}${fileName}`
        : `${currentPath}/${fileName}`;
      await adbManager.deleteFile(remotePath);
      loadFiles(currentPath);
    } catch (err: any) {
      setError(err.message || '删除文件失败');
    }
  }, [currentPath, loadFiles]);

  const handleNavigate = useCallback((fileName: string) => {
    const newPath = currentPath.endsWith('/')
      ? `${currentPath}${fileName}/`
      : `${currentPath}/${fileName}/`;
    loadFiles(newPath);
  }, [currentPath, loadFiles]);

  const handleGoUp = useCallback(() => {
    const parts = currentPath.split('/').filter(Boolean);
    parts.pop();
    const newPath = '/' + parts.join('/') + '/';
    loadFiles(newPath);
  }, [currentPath, loadFiles]);

  const handleFileDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (file) {
      handlePushFile(file);
    }
  }, [handlePushFile]);

  return (
    <div className="file-manager">
      <div className="manager-header">
        <h2>文件管理</h2>
        <div className="manager-actions">
          <button
            className="btn btn-primary"
            onClick={() => loadFiles(currentPath)}
            disabled={loading}
          >
            {loading ? '加载中...' : '刷新'}
          </button>
          <button
            className="btn btn-secondary"
            onClick={() => fileInputRef.current?.click()}
          >
            上传文件
          </button>
          <input
            ref={fileInputRef}
            type="file"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) handlePushFile(file);
            }}
            style={{ display: 'none' }}
          />
        </div>
      </div>

      {error && (
        <div className="error-message">
          <span>{error}</span>
          <button onClick={() => setError('')}>×</button>
        </div>
      )}

      <div className="path-bar">
        <button className="btn btn-small" onClick={handleGoUp}>
          ⬆️ 上级目录
        </button>
        <span className="current-path">{currentPath}</span>
      </div>

      <div
        className="drop-zone"
        onDragOver={(e) => e.preventDefault()}
        onDrop={handleFileDrop}
      >
        <span>拖拽文件到此处上传</span>
      </div>

      <div className="file-list">
        {files.length === 0 ? (
          <div className="empty-state">
            <p>{loading ? '加载中...' : '目录为空'}</p>
          </div>
        ) : (
          <div className="file-grid">
            {files.map(file => (
              <div key={file} className="file-item">
                <span className="file-icon">
                  {file.endsWith('/') ? '📁' : '📄'}
                </span>
                <span
                  className="file-name"
                  title={file}
                  onClick={() => file.endsWith('/') ? handleNavigate(file) : handlePullFile(file)}
                >
                  {file}
                </span>
                <div className="file-actions">
                  <button
                    className="btn btn-small"
                    onClick={() => handlePullFile(file)}
                    title="下载"
                  >
                    ⬇️
                  </button>
                  <button
                    className="btn btn-danger btn-small"
                    onClick={() => handleDelete(file)}
                    title="删除"
                  >
                    🗑️
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default FileManager;
