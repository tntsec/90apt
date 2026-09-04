import { useState, useCallback, useRef } from 'react';
import { adbManager } from '../adb/AdbManager';

function AppManager() {
  const [packages, setPackages] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [installProgress, setInstallProgress] = useState<string>('');
  const [error, setError] = useState<string>('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const loadPackages = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const pkgs = await adbManager.listPackages();
      setPackages(pkgs);
    } catch (err: any) {
      setError(err.message || '加载应用列表失败');
    } finally {
      setLoading(false);
    }
  }, []);

  const handleInstall = useCallback(async (file: File) => {
    setInstallProgress(`正在安装 ${file.name}...`);
    setError('');
    try {
      const result = await adbManager.installApp(file);
      setInstallProgress('');
      alert(`安装成功: ${result}`);
      loadPackages();
    } catch (err: any) {
      setInstallProgress('');
      setError(err.message || '安装失败');
    }
  }, [loadPackages]);

  const handleUninstall = useCallback(async (packageName: string) => {
    if (!confirm(`确定要卸载 ${packageName} 吗？`)) return;

    try {
      await adbManager.uninstallApp(packageName);
      loadPackages();
    } catch (err: any) {
      setError(err.message || '卸载失败');
    }
  }, [loadPackages]);

  const handleFileDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (file?.name.endsWith('.apk')) {
      handleInstall(file);
    }
  }, [handleInstall]);

  const handleFileChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      handleInstall(file);
    }
  }, [handleInstall]);

  const filteredPackages = packages.filter(pkg =>
    pkg.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="app-manager">
      <div className="manager-header">
        <h2>应用管理</h2>
        <div className="manager-actions">
          <button
            className="btn btn-primary"
            onClick={loadPackages}
            disabled={loading}
          >
            {loading ? '加载中...' : '刷新列表'}
          </button>
          <button
            className="btn btn-secondary"
            onClick={() => fileInputRef.current?.click()}
          >
            安装 APK
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".apk"
            onChange={handleFileChange}
            style={{ display: 'none' }}
          />
        </div>
      </div>

      {installProgress && (
        <div className="progress-bar">
          <div className="progress-text">{installProgress}</div>
        </div>
      )}

      {error && (
        <div className="error-message">
          <span>{error}</span>
          <button onClick={() => setError('')}>×</button>
        </div>
      )}

      <div
        className="drop-zone"
        onDragOver={(e) => e.preventDefault()}
        onDrop={handleFileDrop}
      >
        <span>拖拽 APK 文件到此处安装</span>
      </div>

      <div className="search-bar">
        <input
          type="text"
          placeholder="搜索应用..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />
        <span className="search-count">
          {filteredPackages.length} / {packages.length} 个应用
        </span>
      </div>

      <div className="package-list">
        {packages.length === 0 ? (
          <div className="empty-state">
            <p>点击"刷新列表"加载已安装应用</p>
          </div>
        ) : (
          <div className="package-grid">
            {filteredPackages.map(pkg => (
              <div key={pkg} className="package-item">
                <span className="package-name" title={pkg}>{pkg}</span>
                <button
                  className="btn btn-danger btn-small"
                  onClick={() => handleUninstall(pkg)}
                >
                  卸载
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default AppManager;
