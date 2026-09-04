import { Adb, AdbDaemonTransport } from "@yume-chan/adb";
import { AdbDaemonWebUsbDeviceManager, type AdbDaemonWebUsbDevice } from "@yume-chan/adb-daemon-webusb";
import AdbWebCredentialStore from "@yume-chan/adb-credential-web";

export type DeviceState = 'disconnected' | 'connecting' | 'connected' | 'error';

export interface DeviceInfo {
  serial: string;
  name?: string;
  state?: string;
}

export class AdbManager {
  private adb: Adb | null = null;
  private transport: AdbDaemonTransport | null = null;
  private credentialStore: AdbWebCredentialStore;
  private deviceManager: AdbDaemonWebUsbDeviceManager | undefined;

  onStateChange?: (state: DeviceState, info?: string) => void;

  constructor() {
    this.credentialStore = new AdbWebCredentialStore('WebADB@Browser');
    this.deviceManager = AdbDaemonWebUsbDeviceManager.BROWSER;
  }

  isWebUSBSupported(): boolean {
    return !!this.deviceManager;
  }

  getDeviceManager(): AdbDaemonWebUsbDeviceManager | undefined {
    return this.deviceManager;
  }

  async requestDevice(): Promise<AdbDaemonWebUsbDevice | null> {
    if (!this.deviceManager) {
      throw new Error('WebUSB 不受支持');
    }

    this.onStateChange?.('connecting', '正在请求设备权限...');

    try {
      const device = await this.deviceManager.requestDevice();
      if (!device) {
        this.onStateChange?.('disconnected');
        return null;
      }
      return device;
    } catch (error) {
      this.onStateChange?.('error', `请求设备失败: ${error}`);
      throw error;
    }
  }

  async connect(): Promise<Adb> {
    if (this.adb) {
      return this.adb;
    }

    const device = await this.requestDevice();
    if (!device) {
      throw new Error('未选择设备');
    }

    this.onStateChange?.('connecting', '正在建立连接...');

    try {
      const connection = await device.connect();

      this.transport = await AdbDaemonTransport.authenticate({
        serial: device.serial,
        connection,
        credentialStore: this.credentialStore,
      });

      this.adb = new Adb(this.transport);

      this.onStateChange?.('connected', `${device.name || device.serial}`);
      return this.adb;
    } catch (error) {
      this.onStateChange?.('error', `连接失败: ${error}`);
      throw error;
    }
  }

  async disconnect(): Promise<void> {
    if (this.transport) {
      await this.transport.close();
      this.transport = null;
    }
    this.adb = null;
    this.onStateChange?.('disconnected');
  }

  getAdb(): Adb | null {
    return this.adb;
  }

  isConnected(): boolean {
    return this.adb !== null;
  }

  // Shell command execution using noneProtocol.spawnWaitText
  async shell(command: string): Promise<string> {
    if (!this.adb) throw new Error('设备未连接');
    return this.adb.subprocess.noneProtocol.spawnWaitText(command);
  }

  // Install APK via pm install
  async installApp(file: File): Promise<string> {
    if (!this.adb) throw new Error('设备未连接');

    // Use pm install-stream for streaming APK installation
    const process = await this.adb.subprocess.noneProtocol.spawn('pm install -r -d');
    
    // Write the APK data to stdin
    const writer = process.stdin.getWriter();
    const arrayBuffer = await file.arrayBuffer();
    const data = new Uint8Array(arrayBuffer);
    
    try {
      await writer.write(data);
    } finally {
      writer.releaseLock();
    }

    // Read output
    const decoder = new TextDecoder();
    let output = '';
    const reader = process.output.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        output += decoder.decode(value, { stream: true });
      }
    } finally {
      reader.releaseLock();
    }

    await process.exited;
    return output || '安装完成';
  }

  // Uninstall app
  async uninstallApp(packageName: string): Promise<string> {
    return this.shell(`pm uninstall ${packageName}`);
  }

  // List installed packages
  async listPackages(): Promise<string[]> {
    const output = await this.shell('pm list packages');
    return output
      .split('\n')
      .filter(line => line.startsWith('package:'))
      .map(line => line.replace('package:', '').trim())
      .filter(Boolean);
  }

  // Get device properties
  async getDeviceProps(): Promise<Record<string, string>> {
    const props: Record<string, string> = {};
    const output = await this.shell('getprop');
    const lines = output.split('\n');
    for (const line of lines) {
      const match = line.match(/^\[(.+?)\]:\s*\[(.+?)\]$/);
      if (match) {
        props[match[1]] = match[2];
      }
    }
    return props;
  }

  // Enable wireless ADB using tcpip command
  async enableWirelessAdb(port: number = 5555): Promise<string> {
    if (!this.adb) throw new Error('设备未连接');
    return this.adb.tcpip.setPort(port);
  }

  // Pull file from device using sync
  async pullFile(remotePath: string): Promise<Uint8Array> {
    if (!this.adb) throw new Error('设备未连接');

    const sync = await this.adb.sync();

    try {
      const stream = sync.read(remotePath);
      const chunks: Uint8Array[] = [];
      
      const reader = stream.getReader();
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks.push(value);
        }
      } finally {
        reader.releaseLock();
      }

      const totalLength = chunks.reduce((acc, chunk) => acc + chunk.length, 0);
      const result = new Uint8Array(totalLength);
      let offset = 0;
      for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.length;
      }

      return result;
    } finally {
      await sync.dispose();
    }
  }

  // Push file to device using sync
  async pushFile(localData: Uint8Array, remotePath: string): Promise<void> {
    if (!this.adb) throw new Error('设备未连接');

    const sync = await this.adb.sync();
    try {
      const file = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(localData);
          controller.close();
        }
      });

      await sync.write({
        filename: remotePath,
        file: file as any,
        permission: 0o644,
      });
    } finally {
      await sync.dispose();
    }
  }

  // Delete file using rm command
  async deleteFile(path: string): Promise<string> {
    if (!this.adb) throw new Error('设备未连接');
    return this.adb.rm(path, { recursive: true });
  }

  // Reboot device
  async reboot(mode?: 'normal' | 'recovery' | 'bootloader'): Promise<string> {
    if (mode === 'recovery') return this.shell('reboot recovery');
    if (mode === 'bootloader') return this.shell('reboot bootloader');
    return this.shell('reboot');
  }

  // Get battery info
  async getBatteryInfo(): Promise<string> {
    return this.shell('dumpsys battery');
  }

  // Get screen resolution
  async getScreenResolution(): Promise<string> {
    return this.shell('wm size');
  }

  // Get logcat
  async getLogcat(lines: number = 100): Promise<string> {
    return this.shell(`logcat -d -t ${lines}`);
  }

  // Get running processes
  async getRunningProcesses(): Promise<string> {
    return this.shell('ps -A');
  }

  // Input text
  async inputText(text: string): Promise<string> {
    return this.shell(`input text "${text.replace(/"/g, '\\"')}"`);
  }

  // Key event
  async keyEvent(keycode: number): Promise<string> {
    return this.shell(`input keyevent ${keycode}`);
  }

  // Tap screen
  async tap(x: number, y: number): Promise<string> {
    return this.shell(`input tap ${x} ${y}`);
  }

  // Swipe screen
  async swipe(x1: number, y1: number, x2: number, y2: number, duration: number = 300): Promise<string> {
    return this.shell(`input swipe ${x1} ${y1} ${x2} ${y2} ${duration}`);
  }

  // Get device model
  async getModel(): Promise<string> {
    return this.shell('getprop ro.product.model');
  }

  // Get Android version
  async getAndroidVersion(): Promise<string> {
    return this.shell('getprop ro.build.version.release');
  }

  // Get SDK version
  async getSdkVersion(): Promise<string> {
    return this.shell('getprop ro.build.version.sdk');
  }

  // Get manufacturer
  async getManufacturer(): Promise<string> {
    return this.shell('getprop ro.product.manufacturer');
  }
}

export const adbManager = new AdbManager();
