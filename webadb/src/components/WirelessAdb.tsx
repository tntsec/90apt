import { useState, useCallback } from 'react';
import { adbManager } from '../adb/AdbManager';

function WirelessAdb() {
  const [port, setPort] = useState('5555');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>('');
  const [success, setSuccess] = useState<string>('');

  const handleEnable = useCallback(async () => {
    setLoading(true);
    setError('');
    setSuccess('');

    try {
      const result = await adbManager.enableWirelessAdb(parseInt(port));
      setSuccess(`无线 ADB 已启用，端口: ${port}\n设备将监听 TCP 连接`);
    } catch (err: any) {
      setError(err.message || '启用无线 ADB 失败');
    } finally {
      setLoading(false);
    }
  }, [port]);

  return (
    <div className="wireless-adb">
      <div className="manager-header">
        <h2>无线 ADB</h2>
      </div>

      <div className="info-box">
        <h3>说明</h3>
        <ul>
          <li>无线 ADB 需要先通过 USB 连接设备</li>
          <li>启用后，设备将在指定端口监听 TCP 连接</li>
          <li>无线连接需要在同一局域网内</li>
          <li>重启设备后无线 ADB 会自动关闭</li>
        </ul>
      </div>

      <div className="wireless-form">
        <div className="form-group">
          <label>端口号</label>
          <input
            type="number"
            value={port}
            onChange={(e) => setPort(e.target.value)}
            min="1024"
            max="65535"
            placeholder="5555"
          />
        </div>

        <button
          className="btn btn-primary"
          onClick={handleEnable}
          disabled={loading}
        >
          {loading ? '启用中...' : '启用无线 ADB'}
        </button>
      </div>

      {error && (
        <div className="error-message">
          <span>{error}</span>
          <button onClick={() => setError('')}>×</button>
        </div>
      )}

      {success && (
        <div className="success-message">
          <span>{success}</span>
          <button onClick={() => setSuccess('')}>×</button>
        </div>
      )}

      <div className="info-box">
        <h3>连接方式</h3>
        <p>启用无线 ADB 后，可以使用以下方式连接：</p>
        <code>adb connect {window.location.hostname || '设备IP'}:{port}</code>
        <p className="hint">注意：浏览器端的 WebUSB 无法直接进行 TCP 连接</p>
        <p className="hint">无线 ADB 需要配合本地 ADB 客户端使用</p>
      </div>
    </div>
  );
}

export default WirelessAdb;
