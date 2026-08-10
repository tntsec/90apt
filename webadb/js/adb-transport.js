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
    });
  };

  AdbWebUsbTransport.prototype.send = function (bytes) {
    return this.device.transferOut(this.outEndpoint, bytes);
  };

  AdbWebUsbTransport.prototype._fill = function () {
    var self = this;
    return this.device.transferIn(this.inEndpoint, MAX_TRANSFER_SIZE).then(function (res) {
      if (res.status !== 'ok') {
        throw new Error('USB 读取失败: ' + res.status);
      }
      var data = new Uint8Array(res.data.buffer, res.data.byteOffset, res.data.byteLength);
      self._chunks.push(data);
      self._chunkLength += data.byteLength;
    });
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

  AdbWebUsbTransport.prototype.recvPacket = function () {
    var self = this;
    return this.recvBytes(WebADB.HEADER_SIZE).then(function (header) {
      var dv = new DataView(header.buffer, header.byteOffset, WebADB.HEADER_SIZE);
      var command = dv.getUint32(0, true);
      var arg0 = dv.getUint32(4, true);
      var arg1 = dv.getUint32(8, true);
      var length = dv.getUint32(12, true);
      if (length === 0) {
        return { command: command, arg0: arg0, arg1: arg1, length: 0, payload: new Uint8Array(0) };
      }
      return self.recvBytes(length).then(function (payload) {
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
