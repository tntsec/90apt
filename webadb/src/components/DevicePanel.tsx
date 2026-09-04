import { useState, useEffect } from 'react';
import { adbManager, type DeviceState } from '../adb/AdbManager';

interface DevicePanelProps {
  deviceState: DeviceState;
  isConnected: boolean;
}

interface DeviceProperties {
  model?: string;
  manufacturer?: string;
  androidVersion?: string;
  sdkVersion?: string;
  resolution?: string;
}

function DevicePanel({ deviceState, isConnected }: DevicePanelProps) {
  const [props, setProps] = useState<DeviceProperties>({});
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!isConnected) {
      setProps({});
      return;
    }

    const loadProps = async () => {
      setLoading(true);
      try {
        const [model, manufacturer, androidVersion, sdkVersion, resolution] = await Promise.all([
          adbManager.getModel(),
          adbManager.getManufacturer(),
          adbManager.getAndroidVersion(),
          adbManager.getSdkVersion(),
          adbManager.getScreenResolution(),
        ]);

        setProps({
          model: model.trim(),
          manufacturer: manufacturer.trim(),
          androidVersion: androidVersion.trim(),
          sdkVersion: sdkVersion.trim(),
          resolution: resolution.trim().replace('Physical size: ', ''),
        });
      } catch (error) {
        console.error('Failed to load device properties:', error);
      } finally {
        setLoading(false);
      }
    };

    loadProps();
  }, [isConnected]);

  return (
    <div className="device-panel">
      <div className="panel-header">
        <h2>设备信息</h2>
      </div>
      <div className="panel-content">
        {!isConnected ? (
          <div className="empty-state">
            <span className="empty-icon">📱</span>
            <p>未连接设备</p>
          </div>
        ) : loading ? (
          <div className="loading">
            <span className="spinner" />
            <span>加载设备信息...</span>
          </div>
        ) : (
          <div className="device-props">
            <div className="prop-item">
              <span className="prop-label">厂商</span>
              <span className="prop-value">{props.manufacturer || '-'}</span>
            </div>
            <div className="prop-item">
              <span className="prop-label">型号</span>
              <span className="prop-value">{props.model || '-'}</span>
            </div>
            <div className="prop-item">
              <span className="prop-label">Android</span>
              <span className="prop-value">{props.androidVersion || '-'}</span>
            </div>
            <div className="prop-item">
              <span className="prop-label">SDK</span>
              <span className="prop-value">{props.sdkVersion || '-'}</span>
            </div>
            <div className="prop-item">
              <span className="prop-label">分辨率</span>
              <span className="prop-value">{props.resolution || '-'}</span>
            </div>

            <div className="device-actions">
              <button
                className="btn btn-small"
                onClick={() => adbManager.reboot('normal')}
                title="重启设备"
              >
                重启
              </button>
              <button
                className="btn btn-small"
                onClick={() => adbManager.reboot('recovery')}
                title="重启到 Recovery"
              >
                Recovery
              </button>
              <button
                className="btn btn-small"
                onClick={() => adbManager.reboot('bootloader')}
                title="重启到 Bootloader"
              >
                Bootloader
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default DevicePanel;
