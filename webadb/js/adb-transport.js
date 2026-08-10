(function (global) {
  'use strict';

  var ADB_IFACE_CLASS = 0xff;
  var ADB_IFACE_SUBCLASS = 0x42;
  var ADB_IFACE_PROTOCOL = 0x01;
  var MAX_TRANSFER_SIZE = 16384;

  function findAdbInterface(device) {
    var configs = device.configurations;
    if (!configs) return null;
    for (var i = 0; i < configs.length; i++) {
      var config = configs[i];
      for (var j = 0; j < config.interfaces.length; j++) {
        var iface = config.interfaces[j];
        for (var k = 0; k < iface.alternates.length; k++) {
          var alt = iface.alternates[k];
          if (alt.interfaceClass === ADB_IFACE_CLASS &&
              alt.interfaceSubclass === ADB_IFACE_SUBCLASS &&
              alt.interfaceProtocol === ADB_IFACE_PROTOCOL) {
            return { config: config, iface: iface, alt: alt };
          }
        }
      }
    }
    return null;
  }

  function AdbWebUsbTransport(device) {
    this.device = device;
    this.claimed = false;
    this.ifaceNumber = 0;
    this.inEndpoint = null;
    this.outEndpoint = null;
    this._chunks = [];
    this._chunkLength = 0;
  }

  AdbWebUsbTransport.prototype.connect = function () {
    var self = this;
    var openPromise = this.device.opened
      ? Promise.resolve()
      : this.device.open();

    return openPromise.then(function () {
      var found = findAdbInterface(self.device);
      if (!found) {
        throw new Error('未找到 ADB 接口，请确认手机已开启“USB 调试”');
      }
      var configValue = found.config.configurationValue;
      var current = self.device.configuration;
      if (current === null || current.configurationValue !== configValue) {
        return self.device.selectConfiguration(configValue).then(function () {
          return found;
        });
      }
      return found;
    }).then(function (found) {
      self.ifaceNumber = found.iface.interfaceNumber;
      return self.device.claimInterface(self.ifaceNumber).catch(function (e) {
        throw new Error('无法占用 ADB 接口，可能已被其他程序占用：' + e.message);
      });
    }).then(function () {
      self.claimed = true;
      var found = findAdbInterface(self.device);
      var alt = found.alt;
      if (alt.alternateSetting !== 0) {
        return self.device.selectAlternateSetting(self.ifaceNumber, 0).then(function () {
          return found;
        }).catch(function () {
          return found;
        });
      }
      return found;
    }).then(function (found) {
      var inEp = null;
      var outEp = null;
      var endpoints = found.alt.endpoints;
      for (var i = 0; i < endpoints.length; i++) {
        var ep = endpoints[i];
        if (ep.type === 'bulk') {
          if (ep.direction === 'in') inEp = ep;
          else if (ep.direction === 'out') outEp = ep;
        }
      }
      if (!inEp || !outEp) {
        throw new Error('未找到 ADB 数据端点');
      }
      self.inEndpoint = inEp.endpointNumber;
      self.outEndpoint = outEp.endpointNumber;
      self._debug('接口 #' + self.ifaceNumber + ' 配置 ' +
        (found.config ? found.config.configurationValue : '?') +
        ' alt ' + found.alt.alternateSetting +
        ' IN 端点 ' + self.inEndpoint + ' OUT 端点 ' + self.outEndpoint);
    });
  };

  AdbWebUsbTransport.prototype.send = function (bytes) {
    var self = this;
    var dv = new DataView(bytes.buffer, bytes.byteOffset, 24);
    self._debug('发包 cmd=0x' + dv.getUint32(0, true).toString(16) +
      ' arg0=' + dv.getUint32(4, true) + ' arg1=' + dv.getUint32(8, true) +
      ' len=' + dv.getUint32(12, true));
    return this.device.transferOut(this.outEndpoint, bytes);
  };

  AdbWebUsbTransport.prototype._debug = function (msg) {
    if (this.onLog) this.onLog('[transport] ' + msg);
  };

  AdbWebUsbTransport.prototype._fill = function () {
    var self = this;
    var attempts = 0;

    function attempt() {
      attempts++;
      return self.device.transferIn(self.inEndpoint, MAX_TRANSFER_SIZE).then(function (res) {
        if (res.status !== 'ok') {
          throw new Error('USB 读取失败: ' + res.status);
        }
        var data = new Uint8Array(res.data.buffer, res.data.byteOffset, res.data.byteLength);
        self._chunks.push(data);
        self._chunkLength += data.byteLength;
      }).catch(function (err) {
        if (attempts < 3 && /transfer|设备/i.test(err.message)) {
          self._debug('transferIn 失败，' + attempts + '/3 重试：' + err.message);
          return new Promise(function (resolve) { setTimeout(resolve, 500); }).then(attempt);
        }
        throw err;
      });
    }

    return attempt();
  };

  AdbWebUsbTransport.prototype.recvBytes = function (count) {
    var self = this;
    var out = new Uint8Array(count);
    var offset = 0;

    function step() {
      if (offset >= count) return Promise.resolve(out);
      if (self._chunkLength === 0) {
        return self._fill().then(step);
      }
      var chunk = self._chunks[0];
      var take = Math.min(count - offset, chunk.length);
      out.set(chunk.subarray(0, take), offset);
      offset += take;
      if (take === chunk.length) {
        self._chunks.shift();
      } else {
        self._chunks[0] = chunk.subarray(take);
      }
      self._chunkLength -= take;
      return step();
    }

    return step();
  };

  AdbWebUsbTransport.prototype._hex = function (bytes, maxLen) {
    var out = [];
    for (var i = 0; i < bytes.length && i < (maxLen || 32); i++) {
      out.push((bytes[i] >>> 4).toString(16) + (bytes[i] & 0xf).toString(16));
    }
    return out.join(' ');
  };

  AdbWebUsbTransport.prototype.recvPacket = function () {
    var self = this;
    return this.recvBytes(WebADB.HEADER_SIZE).then(function (header) {
      var dv = new DataView(header.buffer, header.byteOffset, WebADB.HEADER_SIZE);
      var command = dv.getUint32(0, true);
      var arg0 = dv.getUint32(4, true);
      var arg1 = dv.getUint32(8, true);
      var length = dv.getUint32(12, true);
      var known = [WebADB.Cmd.SYNC, WebADB.Cmd.CNXN, WebADB.Cmd.AUTH,
                   WebADB.Cmd.OPEN, WebADB.Cmd.OKAY, WebADB.Cmd.CLSE, WebADB.Cmd.WRTE];
      if (known.indexOf(command) === -1) {
        throw new Error('收到非 ADB 报文（command=0x' + command.toString(16) +
          ' 头：' + self._hex(header) + '），接口可能选错');
      }
      if (length > 16 * 1024 * 1024) {
        throw new Error('报文长度异常（' + length + ' 头：' + self._hex(header) + '）');
      }
      self._debug('收包 cmd=0x' + command.toString(16) + ' arg0=' + arg0 + ' arg1=' + arg1 + ' len=' + length);
      if (length === 0) {
        return { command: command, arg0: arg0, arg1: arg1, length: 0, payload: new Uint8Array(0) };
      }
      return self.recvBytes(length).then(function (payload) {
        if (command === WebADB.Cmd.AUTH && arg0 === WebADB.AuthType.TOKEN) {
          self._debug('token=' + self._hex(payload, 32));
        }
        return { command: command, arg0: arg0, arg1: arg1, length: length, payload: payload };
      });
    });
  };

  AdbWebUsbTransport.prototype.disconnect = function () {
    var self = this;
    var release = this.claimed
      ? this.device.releaseInterface(this.ifaceNumber).catch(function () {})
      : Promise.resolve();
    return release.then(function () {
      self.claimed = false;
      if (self.device.opened) {
        return self.device.close().catch(function () {});
      }
    });
  };

  global.WebADB = Object.assign(global.WebADB || {}, {
    AdbWebUsbTransport: AdbWebUsbTransport
  });
})(window);
