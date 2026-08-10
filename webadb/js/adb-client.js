(function (global) {
  'use strict';

  var Cmd = WebADB.Cmd;
  var AuthType = WebADB.AuthType;
  var buildPacket = WebADB.buildPacket;
  var textEncode = WebADB.textEncode;
  var textDecode = WebADB.textDecode;

  var CONNECT_TIMEOUT_MS = 60000;

  function AdbClient(transport, options) {
    this.transport = transport;
    this.comment = (options && options.comment) || 'webadb@local';
    this.authenticated = false;
    this.pending = new Map();
    this.nextLocalId = 0;
    this.running = false;
    this.closing = false;
    this.onError = null;
    this.onClose = null;
  }

  AdbClient.prototype.connect = function () {
    var self = this;
    var banner = 'host::features=cmd,shell_v2,stat_v2,ls_v2,fixed_push_mkdir,apex,abb\0';
    var pubBlob = null;

    return this.transport.send(buildPacket(Cmd.CNXN, WebADB.VERSION, WebADB.MAXDATA, textEncode(banner))).then(function () {
      return WebADB.Crypto.getOrCreateKey(self.comment);
    }).then(function (jwk) {
      pubBlob = WebADB.Crypto.buildPublicKeyBlob(jwk, self.comment);
      return self._authLoop(jwk, pubBlob);
    }).then(function () {
      self.authenticated = true;
      self.running = true;
      self._startMessageLoop();
      return true;
    });
  };

  AdbClient.prototype._authLoop = function (jwk, pubBlob) {
    var self = this;
    var deadline = Date.now() + CONNECT_TIMEOUT_MS;

    function step() {
      if (Date.now() > deadline) {
        return Promise.reject(new Error('连接超时，请在手机上确认“允许 USB 调试”'));
      }
      return self.transport.recvPacket().then(function (pkt) {
        if (pkt.command === Cmd.CNXN) {
          return true;
        }
        if (pkt.command === Cmd.AUTH) {
          if (pkt.arg0 === AuthType.TOKEN) {
            return WebADB.Crypto.signToken(pkt.payload, jwk).then(function (signature) {
              return self.transport.send(buildPacket(Cmd.AUTH, AuthType.SIGNATURE, 0, signature));
            }).then(step);
          } else if (pkt.arg0 === AuthType.RSAPUBLICKEY) {
            return self.transport.send(buildPacket(Cmd.AUTH, AuthType.RSAPUBLICKEY, 0, textEncode(pubBlob))).then(step);
          }
          return step();
        }
        return step();
      });
    }

    return step();
  };

  AdbClient.prototype._startMessageLoop = function () {
    var self = this;
    (function loop() {
      if (!self.running) return;
      self.transport.recvPacket().then(function (pkt) {
        self._handlePacket(pkt);
        loop();
      }).catch(function (err) {
        self.running = false;
        self._rejectAll(err);
        if (!self.closing) {
          if (self.onError) self.onError(err);
          if (self.onClose) self.onClose(err);
        }
      });
    })();
  };

  AdbClient.prototype._handlePacket = function (pkt) {
    var pending;
    switch (pkt.command) {
      case Cmd.WRTE:
        pending = this.pending.get(pkt.arg1);
        if (pending) {
          pending.output += textDecode(pkt.payload);
          this.transport.send(buildPacket(Cmd.OKAY, pkt.arg1, pkt.arg0)).catch(function () {});
        }
        break;
      case Cmd.OKAY:
        pending = this.pending.get(pkt.arg1);
        if (pending) pending.okayed = true;
        break;
      case Cmd.CLSE:
        pending = this.pending.get(pkt.arg1);
        if (pending) {
          this.pending.delete(pkt.arg1);
          this.transport.send(buildPacket(Cmd.CLSE, pkt.arg1, pkt.arg0)).catch(function () {});
          pending.resolve(pending.output);
        }
        break;
      default:
        break;
    }
  };

  AdbClient.prototype._rejectAll = function (err) {
    var self = this;
    this.pending.forEach(function (pending) {
      pending.reject(err);
    });
    this.pending.clear();
  };

  AdbClient.prototype.execService = function (name) {
    var self = this;
    if (!this.running) {
      return Promise.reject(new Error('连接已断开'));
    }
    var localId = ++this.nextLocalId;
    return new Promise(function (resolve, reject) {
      self.pending.set(localId, { output: '', resolve: resolve, reject: reject });
      self.transport.send(buildPacket(Cmd.OPEN, localId, 0, textEncode(name))).catch(function (err) {
        self.pending.delete(localId);
        reject(err);
      });
    });
  };

  AdbClient.prototype.getprop = function (name) {
    return this.execService('shell:getprop ' + name).then(function (out) {
      return out.replace(/\0+$/g, '').trim();
    });
  };

  AdbClient.prototype.enableWifiAdb = function (port) {
    return this.execService('tcpip:' + port);
  };

  AdbClient.prototype.disableWifiAdb = function () {
    return this.execService('usb');
  };

  AdbClient.prototype.getWifiIp = function () {
    var self = this;
    var keys = ['dhcp.wlan0.ipaddress', 'dhcp.wifi.ipaddress', 'wlan0.ipaddress'];
    var chain = Promise.resolve(null);
    keys.forEach(function (key) {
      chain = chain.then(function (found) {
        if (found) return found;
        return self.getprop(key).then(function (value) {
          if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return value;
          return null;
        }).catch(function () {
          return null;
        });
      });
    });
    return chain.then(function (found) {
      if (found) return found;
      return self.execService('shell:ip addr show wlan0').then(function (out) {
        var match = out.match(/inet\s+(\d{1,3}(?:\.\d{1,3}){3})\b/);
        return match ? match[1] : null;
      }).catch(function () {
        return null;
      });
    });
  };

  AdbClient.prototype.getSystemProperties = function () {
    var self = this;
    var tasks = [
      ['manufacturer', 'ro.product.manufacturer'],
      ['model', 'ro.product.model'],
      ['version', 'ro.build.version.release'],
      ['serial', 'ro.serialno'],
      ['buildId', 'ro.build.id']
    ];
    var result = {};
    var chain = Promise.resolve();
    tasks.forEach(function (task) {
      chain = chain.then(function () {
        return self.getprop(task[1]).then(function (value) {
          result[task[0]] = value;
        }).catch(function () {
          result[task[0]] = '';
        });
      });
    });
    return chain.then(function () {
      return result;
    });
  };

  AdbClient.prototype.close = function () {
    this.closing = true;
    this.running = false;
    return this.transport.disconnect();
  };

  global.WebADB = Object.assign(global.WebADB || {}, {
    AdbClient: AdbClient
  });
})(window);
