import type { DeviceState } from '../adb/AdbManager';

interface HeaderProps {
  deviceState: DeviceState;
  deviceInfo: string;
  onConnect: () => void;
  onDisconnect: () => void;
}

function Header({ deviceState, deviceInfo, onConnect, onDisconnect }: HeaderProps) {
  const isConnected = deviceState === 'connected';
  const isConnecting = deviceState === 'connecting';

  return (
    <header className="header">
      <div className="header-left">
        <h1 className="logo">
          <span className="logo-icon">📱</span>
          WebADB
        </h1>
        <span className="version">v1.0.0</span>
      </div>

      <div className="header-center">
        <div className="status-indicator">
          <span className={`status-dot ${deviceState}`} />
          <span className="status-text">
            {deviceState === 'connected' && `已连接: ${deviceInfo}`}
            {deviceState === 'disconnected' && '未连接'}
            {deviceState === 'connecting' && '连接中...'}
            {deviceState === 'error' && '连接错误'}
          </span>
        </div>
      </div>

      <div className="header-right">
        {isConnected ? (
          <button
            className="btn btn-danger"
            onClick={onDisconnect}
          >
            断开连接
          </button>
        ) : (
          <button
            className="btn btn-primary"
            onClick={onConnect}
            disabled={isConnecting}
          >
            {isConnecting ? '连接中...' : '连接设备'}
          </button>
        )}
      </div>
    </header>
  );
}

export default Header;
