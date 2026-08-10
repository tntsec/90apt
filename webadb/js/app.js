(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };

  var logEl = $('log');
  var client = null;
  var usbDevice = null;

  function log(message, type) {
    var line = document.createElement('div');
    line.className = 'log-line ' + (type || 'info');
    var time = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    line.textContent = '[' + time + '] ' + message;
    logEl.appendChild(line);
    logEl.scrollTop = logEl.scrollHeight;
  }

  function setStatus(text, cls) {
    var el = $('conn-status');
    el.textContent = text;
    el.className = 'status-badge' + (cls ? ' ' + cls : '');
  }

  function setTip(message, cls) {
    var el = $('wifi-tip');
    if (!message) {
      el.className = 'tip';
      el.textContent = '';
      return;
    }
    el.textContent = message;
    el.className = 'tip show' + (cls ? ' ' + cls : '');
  }

  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function updateButtons() {
    var connected = !!client;
    $('btn-disconnect').disabled = !connected;
    $('btn-wifi-on').disabled = !connected;
    $('btn-wifi-off').disabled = !connected;
  }

  function renderDeviceInfo(info) {
    var el = $('device-info');
    if (!info) {
      el.innerHTML = '<div class="empty-hint">尚未连接设备</div>';
      return;
    }
    var rows = [
      ['设备型号', info.model],
      ['制造商', info.manufacturer],
      ['Android 版本', info.version],
      ['序列号', info.serial],
      ['Build', info.buildId]
    ];
    el.innerHTML = rows.map(function (row) {
      return '<div class="info-row"><span class="info-label">' + row[0] +
        '</span><span class="info-value">' + escapeHtml(row[1] || '-') + '</span></div>';
    }).join('');
  }

  function cleanup() {
    var closing = client;
    client = null;
    usbDevice = null;
    if (closing) {
      closing.close().catch(function () {});
    }
    updateButtons();
    renderDeviceInfo(null);
  }

  function handleTransportError(err) {
    log('连接中断：' + err.message, 'error');
    setStatus('连接断开', 'bad');
    cleanup();
  }

  function handleConnect() {
    if (!navigator.usb) {
      log('当前浏览器不支持 WebUSB，请使用 Chrome / Edge，并通过 http://localhost 或 HTTPS 访问', 'error');
      return;
    }
    navigator.usb.requestDevice({ filters: [] }).then(function (device) {
      usbDevice = device;
      var name = device.productName || device.manufacturerName || device.serialNumber || '未知设备';
      log('已选择设备：' + name);
      var transport = new WebADB.AdbWebUsbTransport(device);
      transport.onLog = function (msg) { log(msg, 'info'); };
      return transport.connect().then(function () {
        log('已占用 ADB 接口，正在建立连接…');
        client = new WebADB.AdbClient(transport, { comment: 'webadb@local' });
        client.onError = handleTransportError;
        client.onClose = handleTransportError;
        client.onStatus = function (msg) { log(msg, 'warn'); };
        return client.connect();
      });
    }).then(function () {
      setStatus('已连接', 'ok');
      log('ADB 连接成功', 'success');
      return client.getSystemProperties();
    }).then(function (info) {
      renderDeviceInfo(info);
      var summary = info.manufacturer + ' ' + info.model + '（Android ' + (info.version || '?') + '）';
      log('设备信息：' + summary, 'info');
      updateButtons();
    }).catch(function (err) {
      log('连接失败：' + err.message, 'error');
      cleanup();
      setStatus('未连接');
    });
  }

  function handleDisconnect() {
    cleanup();
    setStatus('未连接');
    setTip('');
    log('已断开连接');
  }

  function handleWifiOn() {
    if (!client) return;
    $('btn-wifi-on').disabled = true;
    setTip('');
    log('正在开启无线 ADB（端口 5555）…');
    var ip = null;
    client.getWifiIp().then(function (value) {
      ip = value;
      log('设备 Wi-Fi IP：' + (value || '未知'));
      return client.enableWifiAdb(5555);
    }).then(function (out) {
      if (out && out.trim()) log('adbd 输出：' + out.trim(), 'info');
      return finishWifiOn(ip);
    }).catch(function (err) {
      return finishWifiOn(ip, err);
    });
  }

  function finishWifiOn(ip, err) {
    if (err && !/连接|断开|USB|中断/i.test(err.message)) {
      log('开启无线 ADB 失败：' + err.message, 'error');
      $('btn-wifi-on').disabled = !client;
      return;
    }
    log('已发送 tcpip 5555，adbd 正在重启，USB 连接将断开。', 'success');
    if (ip) {
      var cmd = 'adb connect ' + ip + ':5555';
      setTip('无线连接命令：\n' + cmd + '\n\n在电脑命令行中执行即可无线连接（无需密码）。', 'success');
      log('现在可在电脑命令行执行：' + cmd, 'success');
    } else {
      setTip('无法自动获取手机 IP。请在手机「设置 → WLAN」查看 IP，然后执行：\nadb connect <手机IP>:5555', 'warn');
      log('请在手机「设置 → WLAN」查看 IP，然后执行：adb connect <手机IP>:5555', 'info');
    }
    setStatus('无线已开启');
    cleanup();
  }

  function handleWifiOff() {
    if (!client) return;
    $('btn-wifi-off').disabled = true;
    setTip('');
    log('正在关闭无线 ADB…');
    client.disableWifiAdb().then(function () {
      log('已执行 adb usb，adbd 切回 USB 模式。', 'success');
      setTip('无线 ADB 已关闭，adbd 已切回 USB 模式。');
    }).catch(function (err) {
      log('关闭命令已发送（adbd 可能正在重启）：' + err.message, 'warn');
      setTip('已发送 adb usb。如果连接已断开，请重新插拔 USB 或重新连接设备。', 'warn');
    }).then(function () {
      $('btn-wifi-off').disabled = !client;
    });
  }

  function init() {
    $('btn-connect').addEventListener('click', handleConnect);
    $('btn-disconnect').addEventListener('click', handleDisconnect);
    $('btn-wifi-on').addEventListener('click', handleWifiOn);
    $('btn-wifi-off').addEventListener('click', handleWifiOff);
    $('btn-clear-log').addEventListener('click', function () { logEl.innerHTML = ''; });

    if (!navigator.usb) {
      setStatus('不支持', 'bad');
      log('当前浏览器不支持 WebUSB。请使用最新版 Chrome 或 Edge。', 'error');
    } else if (location.protocol !== 'https:' && location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') {
      setStatus('环境异常', 'bad');
      log('WebUSB 需要安全上下文（HTTPS 或 localhost）。请通过 http://localhost 访问本页面。', 'error');
    } else {
      log('就绪。请用 USB 连接已开启「USB 调试」的安卓手机。', 'info');
    }

    if (navigator.usb) {
      navigator.usb.addEventListener('disconnect', function (e) {
        if (usbDevice && e.device && e.device === usbDevice) {
          log('检测到 USB 设备已拔出', 'warn');
          setStatus('连接断开', 'bad');
          cleanup();
        }
      });
    }

    updateButtons();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
