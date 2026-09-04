import { useState, useCallback, useRef, useEffect } from 'react';
import { adbManager, type DeviceState } from './adb/AdbManager';
import Header from './components/Header';
import DevicePanel from './components/DevicePanel';
import Terminal from './components/Terminal';
import AppManager from './components/AppManager';
import FileManager from './components/FileManager';
import WirelessAdb from './components/WirelessAdb';

type TabId = 'terminal' | 'apps' | 'files' | 'wireless';

function App() {
  const [deviceState, setDeviceState] = useState<DeviceState>('disconnected');
  const [deviceInfo, setDeviceInfo] = useState<string>('');
  const [activeTab, setActiveTab] = useState<TabId>('terminal');
  const [errorMsg, setErrorMsg] = useState<string>('');

  const handleStateChange = useCallback((state: DeviceState, info?: string) => {
    setDeviceState(state);
    if (info) setDeviceInfo(info);
    if (state === 'error' && info) {
      setErrorMsg(info);
      setTimeout(() => setErrorMsg(''), 5000);
    }
  }, []);

  useEffect(() => {
    adbManager.onStateChange = handleStateChange;
    return () => {
      adbManager.onStateChange = undefined;
    };
  }, [handleStateChange]);

  const handleConnect = useCallback(async () => {
    try {
      setErrorMsg('');
      await adbManager.connect();
    } catch (error: any) {
      setErrorMsg(error.message || '连接失败');
    }
  }, []);

  const handleDisconnect = useCallback(async () => {
    try {
      await adbManager.disconnect();
    } catch (error: any) {
      setErrorMsg(error.message || '断开连接失败');
    }
  }, []);

  const isConnected = deviceState === 'connected';

  const tabs: { id: TabId; label: string; icon: string }[] = [
    { id: 'terminal', label: 'Shell 终端', icon: '>' },
    { id: 'apps', label: '应用管理', icon: '📱' },
    { id: 'files', label: '文件管理', icon: '📁' },
    { id: 'wireless', label: '无线 ADB', icon: '📶' },
  ];

  return (
    <div className="app">
      <Header
        deviceState={deviceState}
        deviceInfo={deviceInfo}
        onConnect={handleConnect}
        onDisconnect={handleDisconnect}
      />

      {errorMsg && (
        <div className="error-banner">
          <span>{errorMsg}</span>
          <button onClick={() => setErrorMsg('')}>×</button>
        </div>
      )}

      <div className="main-content">
        <DevicePanel
          deviceState={deviceState}
          isConnected={isConnected}
        />

        <div className="tab-container">
          <div className="tab-bar">
            {tabs.map(tab => (
              <button
                key={tab.id}
                className={`tab-button ${activeTab === tab.id ? 'active' : ''}`}
                onClick={() => setActiveTab(tab.id)}
                disabled={!isConnected}
              >
                <span className="tab-icon">{tab.icon}</span>
                {tab.label}
              </button>
            ))}
          </div>

          <div className="tab-content">
            {!isConnected ? (
              <div className="connect-hint">
                <div className="hint-icon">🔌</div>
                <p>请连接 Android 设备</p>
                <p className="hint-sub">使用 USB 数据线连接设备，然后点击"连接设备"</p>
                <p className="hint-sub">确保设备已开启 USB 调试</p>
              </div>
            ) : (
              <>
                {activeTab === 'terminal' && <Terminal />}
                {activeTab === 'apps' && <AppManager />}
                {activeTab === 'files' && <FileManager />}
                {activeTab === 'wireless' && <WirelessAdb />}
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
