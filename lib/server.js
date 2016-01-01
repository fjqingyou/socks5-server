'use strict';

var net = require('net');
var dgram = require('dgram');
var util = require('util');
var EventEmitter = require('events');

var once = require('once');
var ip = require('ip');
var debug = require('debug')('s5server');
var valueToKey = require('./util').valueToKey;

var SOCKS5_CONST = require('./constants');
var VERSION = SOCKS5_CONST.VERSION;
var AUTH_METHODS = SOCKS5_CONST.AUTH_METHODS;
var AUTH_STATUS = SOCKS5_CONST.AUTH_STATUS;
var COMMAND = SOCKS5_CONST.COMMAND;
var ADDRTYPE = SOCKS5_CONST.ADDRTYPE;
var REQUEST_STATUS = SOCKS5_CONST.REQUEST_STATUS;
var RSV = SOCKS5_CONST.RSV;

var slice = Array.prototype.slice;

var defaults = {
  timeout: 5 * 60 * 1000
};

function Socks5Server(options) {
  var self = this;
  options = options || {};
  var timeout = options.timeout || defaults.timeout;

  this.allow_auth_methods = [];

  this.server = net.createServer(function(connection) {
    debug('connection from:', connection.remoteAddress, connection.remotePort, connection.remoteFamily);

    connection.setTimeout(timeout);
    connection.once('data', function(data) {
      this.emit('authmethod', data);
    });

    connection.on('authmethod', function(data) {
      var auth_method = self.onAuthmethod(data);
      this.auth_method = auth_method;
      debug('auth method:', valueToKey(AUTH_METHODS,auth_method));

      var buffer = new Buffer(2);
      buffer[0] = VERSION;
      if (auth_method === AUTH_STATUS.FAILURE) {
        buffer[1] = AUTH_STATUS.FAILURE;
        return this.end(buffer);
      }
      buffer[1] = auth_method;
      this.write(buffer);

      if (auth_method === AUTH_METHODS.NOAUTH) {
        this.once('data', function(data) {
          connection.emit('request', data);
        });
      } else if (auth_method === AUTH_METHODS.USERNAME_PASSWORD) {
        this.once('data', function(data) {
          this.emit('handshake', data);
        });
      }
    });

    connection.on('handshake', function(data) {
      var buffer = new Buffer(2);
      buffer[0] = VERSION;

      if (self.onHandshake(this.auth_method, data)) {
        buffer[1] = AUTH_STATUS.SUCCESS;
        this.write(buffer);
        this.once('data', function(data) {
          this.emit('request', data);
        });
      } else {
        buffer[1] = AUTH_STATUS.FAILURE;
        this.end(buffer);
      }
    });

    connection.on('request', function(data) {
      var version = data[0];
      var command = data[1];
      var addrtype = data[3];

      var buffer = new Buffer(2);
      buffer[0] = VERSION;
      if (version !== VERSION) {
        buffer[1] = REQUEST_STATUS.CONNECTION_NOT_ALLOWED;
        return this.end(buffer);
      } else if (command == valueToKey(COMMAND, command)) {
        buffer[1] = REQUEST_STATUS.COMMAND_NOT_SUPPORTED;
        return this.end(buffer);
      } else if (addrtype == valueToKey(ADDRTYPE, addrtype)) {
        buffer[1] = REQUEST_STATUS.ADDRTYPE_NOT_SUPPORTED;
        return this.end(buffer);
      }

      self.onRequest(data, function(err, sock) {
        var buffer = null;
        if (err) {
          debug('request error', valueToKey(REQUEST_STATUS, err.code));
          buffer = new Buffer(2);
          buffer[0] = VERSION;
          switch (err.code) {
            case 'ECONNREFUSED':
              buffer[1] = REQUEST_STATUS.CONNECTION_REFUSED;
              break;
            case 'ETIMEDOUT':
              buffer[1] = REQUEST_STATUS.TTL_EXPIRED;
              break;
            case 'ECONNRESET':
              buffer[1] = REQUEST_STATUS.HOST_UNREACHABLE;
              break;
            default:
              buffer[1] = REQUEST_STATUS.SERVER_FAILURE;
              break;
          }
          connection.end(buffer);
        } else if (command === COMMAND.CONNECT) {
          var remote = sock;
          debug('connected remote:', remote.remoteAddress, remote.remotePort);
          buffer = new Buffer(data);
          buffer[1] = REQUEST_STATUS.SUCCESS;
          buffer[2] = RSV;
          connection.write(buffer);
          connection.pipe(remote);
          remote.pipe(connection);
        } else if (command === COMMAND.UDP_ASSOCIATE) {
          var address = sock.address();

          buffer = new Buffer(data);
          buffer[0] = VERSION;
          buffer[1] = REQUEST_STATUS.SUCCESS;
          buffer[2] = RSV;

          debug('COMMAND.UDP_ASSOCIATE', address);
          var addrBuf = ip.toBuffer(address.address);
          var addrLen = addrBuf.length;
          addrBuf.copy(buffer, 4);
          buffer.writeUInt16BE(address.port, addrLen + 4);
          connection.write(buffer);

          connection.on('close', function() {
            debug('close udp socket since connection closed', address);
            sock.close();
          });
        }
      });
    });

    connection.on('error', function() {
      debug('connection error', arguments);
    });
    connection.on('timeout', function() {
      debug('connection timeout', arguments);
      connection.end();
    });
  });

  return this;
}

util.inherits(Socks5Server, EventEmitter);

Socks5Server.prototype.default_auth_methods = [];
Socks5Server.prototype.default_auth_methods[AUTH_METHODS.NOAUTH] = function() {};
Socks5Server.prototype.default_auth_methods[AUTH_METHODS.USERNAME_PASSWORD] = function(data, options) {
  var version = data[0];
  if (version !== 0x01) {
    return false;
  }

  var usernameLen = data[1];
  // var passwordLen = data[usernameLen + 2];
  var username = data.toString('utf8', 2, usernameLen + 2);
  var password = data.toString('utf8', usernameLen + 3);

  if (username === options.username && password === options.password) {
    return true;
  } else {
    return false;
  }
};

Socks5Server.prototype.registerAuth = function(method, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  this.allow_auth_methods[method] = {
    options: options,
    authorize: callback || this.default_auth_methods[method]
  };
};

/*
 * +----+----------+----------+
 * |VER | NMETHODS | METHODS  |
 * +----+----------+----------+
 * | 1  |    1     | 1 to 255 |
 * +----+----------+----------+
 */
Socks5Server.prototype.onAuthmethod = function(data) {
  var verion = data[0];
  var nmthods = data[1];

  if (verion !== VERSION) {
    return AUTH_STATUS.FAILURE;
  }

  for (var i = 0; i < nmthods; i++) {
    var method = data[i + 2];
    if (this.allow_auth_methods[method]) {
      return method;
    }
  }

  return AUTH_STATUS.FAILURE;
};

Socks5Server.prototype.onHandshake = function(method, data) {
  var auth_method = this.allow_auth_methods[method];

  if (auth_method) {
    var options = auth_method.options;
    var authorize = auth_method.authorize;
    return authorize(data, options);
  }

  return false;
};

var parseHostPort = function(data) {
  var addrtype = data[3];
  var host = null;
  var port = null;

  try {
    switch (addrtype) {
      case ADDRTYPE.IP_V4:
        host = util.format('%s.%s.%s.%s', data[4], data[5], data[6], data[7]);
        port = data.readUInt16BE(8);
        // ensure a valid ipv4 format
        if (!net.isIPv4(host)) {
          host = null;
        }
        break;
      case ADDRTYPE.DOMAINNAME:
        var domainLen = data[4];
        host = data.toString('utf8', 5, domainLen + 5);
        port = data.readUInt16BE(domainLen + 5);
        break;
      case ADDRTYPE.IP_V6:
        host = data.slice(4, 20);
        port = data.readUInt16BE(20);
        // ensure a valid ipv6 format
        if (!net.isIPv6(host)) {
          host = null;
        }
        break;
      default:
        // REQUEST_STATUS.ADDRTYPE_NOT_SUPPORTED
        break;
    }
    debug('parseHostPort:', valueToKey(ADDRTYPE, addrtype), host, port);

    if (host && port) {
      return {
        host: host,
        port: port
      };
    }
  } catch (err) {
    // do nothing, bcz it will return false later
  }

  return false;
};

Socks5Server.prototype._connect = function(data, callback) {
  callback = once(callback);

  var addr = parseHostPort(data);

  if (addr) {
    var remote = net.createConnection(addr.port, addr.host);
    remote.on('connect', function() {
      callback(null, remote);
    });
    remote.on('error', callback);
  } else {
    callback({
      code: REQUEST_STATUS.ADDRTYPE_NOT_SUPPORTED
    });
  }
};

Socks5Server.prototype._udpassociate = function(data, callback) {
  var addrtype = data[3];
  var clientAddress = parseHostPort(data);
  var type = null;
  if (addrtype === ADDRTYPE.IP_V4) {
    type = 'udp4';
  } else if (addrtype === ADDRTYPE.IP_V6) {
    type = 'udp6';
  }

  if (clientAddress && type) {
    var sock = dgram.createSocket(type);
    sock.bind(function() {
      callback(null, sock);
    });
    sock.on('message', function(msg, rinfo) {
      debug('onMessage', rinfo, clientAddress);
      if (rinfo.port === clientAddress.port) {
        var address = parseHostPort(msg);
        debug('remote udp server address:', address);

        if (address) {
          sock.send(msg, 10, msg.length - 10, address.port, address.host);
        }
      } else {
        debug('response from remte udp server');
        var buffer = new Buffer(data.length + msg.length);
        buffer.fill(0);
        buffer[3] = data[3];
        var addrBuf = ip.toBuffer(rinfo.address);
        var addrLen = addrBuf.length;
        addrBuf.copy(buffer, 4);
        buffer.writeUInt16BE(rinfo.port, addrLen + 4);
        msg.copy(buffer, addrLen + 6);
        sock.send(buffer, 0, buffer.length, clientAddress.port, clientAddress.host);
      }
    });
  } else {
    callback({
      code: REQUEST_STATUS.ADDRTYPE_NOT_SUPPORTED
    });
  }
};

/*
 * +----+-----+-------+------+----------+----------+
 * |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
 * +----+-----+-------+------+----------+----------+
 * | 1  |  1  | X'00' |  1   | Variable |    2     |
 * +----+-----+-------+------+----------+----------+
 */
Socks5Server.prototype.onRequest = function(data, callback) {
  var command = data[1];
  var addrtype = data[3];
  debug('onRequest:', 'command:', valueToKey(COMMAND, command), ', addrtype:', valueToKey(ADDRTYPE, addrtype));

  switch (command) {
    case COMMAND.CONNECT:
      this._connect(data, callback);
      break;
    // case COMMAND.BIND:
    //   break;
    case COMMAND.UDP_ASSOCIATE:
      this._udpassociate(data, callback);
      break;
    default:
      return callback({
        code: REQUEST_STATUS.COMMAND_NOT_SUPPORTED
      });
  }
};

Socks5Server.prototype.listen = function() {
  var args = slice.call(arguments);
  this.server.listen.apply(this.server, args);
};

module.exports = Socks5Server;
