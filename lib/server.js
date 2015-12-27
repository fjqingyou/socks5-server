'use strict';

var net = require('net');
var util = require('util');
var EventEmitter = require('events');

var once = require('once');
var debug = require('debug')('s5server');
var valueToKey = require('./util').valueToKey;

var SOCKS5_CONST = require('./const');
var VERSION = SOCKS5_CONST.VERSION;
var AUTH_METHODS = SOCKS5_CONST.AUTH_METHODS;
var AUTH_STATUS = SOCKS5_CONST.AUTH_STATUS;
var COMMAND = SOCKS5_CONST.COMMAND;
var ADDRTYPE = SOCKS5_CONST.ADDRTYPE;
var REQUEST_STATUS = SOCKS5_CONST.REQUEST_STATUS;
var RSV = SOCKS5_CONST.RSV;

var slice = Array.prototype.slice;

function Socks5Server() {
  var self = this;

  this.allow_auth_methods = [];

  this.server = net.createServer(function(connection) {
    var remote = null;
    debug('new connection', connection.remoteAddress, connection.remotePort, connection.remoteFamily);

    connection.once('data', function(data) {
      this.emit('authmethod', data);
    });

    connection.on('authmethod', function(data) {
      var auth_method = self.onAuthmethod(data);
      this.auth_method = auth_method;
      debug('authmethod:', valueToKey(AUTH_METHODS,auth_method));

      var buffer = new Buffer(2);
      buffer[0] = VERSION;
      if (auth_method === AUTH_STATUS.FAILURE) {
        buffer[1] = AUTH_STATUS.FAILURE;
        this.end(buffer);
      } else {
        buffer[1] = auth_method;
        this.write(buffer);
      }

      if (auth_method === AUTH_METHODS.NOAUTH) {
        this.once('data', function(data) {
          connection.emit('request', data);
        })
      } else if (auth_method === AUTH_METHODS.USERNAME_PASSWORD) {
        this.once('data', function(data) {
          this.emit('handshake', data);
        })
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
        })
      } else {
        buffer[1] = AUTH_STATUS.FAILURE;
        this.end(buffer);
      }
    });

    connection.on('request', function(data) {
      self.onRequest(data, function(err, sock) {
        if (err) {
          debug('request error', err.code);
          var buffer = new Buffer(2);
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
            case REQUEST_STATUS.COMMAND_NOT_SUPPORTED:
              buffer[1] = REQUEST_STATUS.COMMAND_NOT_SUPPORTED
              break;
            case REQUEST_STATUS.ADDRTYPE_NOT_SUPPORTED:
              buffer[1] = REQUEST_STATUS.ADDRTYPE_NOT_SUPPORTED
              break;
            default:
              buffer[1] = REQUEST_STATUS.SERVER_FAILURE;
              break;
          }
          connection.end(buffer);
        } else {
          remote = sock;
          debug('conn:', connection.remoteAddress, connection.remotePort);
          debug('remote:', remote.remoteAddress, remote.remotePort);
          var buffer = new Buffer(data);
          buffer[1] = REQUEST_STATUS.SUCCESS;
          buffer[2] = RSV;
          connection.write(buffer);
          // remote.on('error', function(error) {
          //   debug('remote error', error);
          // })
          // remote.on('end', function() {
          //   debug('remote end');
          // })
          // remote.on('close', function() {
          //   debug('remote close');
          // })
          // remote.on('timeout', function() {
          //   debug('remote timeout');
          // });
          connection.pipe(remote);
          remote.pipe(connection);
        }
      });
    });

    // connection.on('end', function() {
    //   debug('connection end');
    // });
    connection.on('error', function(err) {
      debug('connection error', err);
    })
    // connection.on('close', function() {
    //   debug('connection close');
    // });
    // connection.on('timeout', function() {
    //   debug('connection timeout');
    // });
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
  var passwordLen = data[usernameLen + 2];
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

  if (verion !== 0x05) {
    return 0xff;
  }

  for (var i = 0; i < nmthods; i++) {
    var method = data[i + 2];
    if (this.allow_auth_methods[method]) {
      return method;
    }
  }

  return 0xff;
};

Socks5Server.prototype.onHandshake = function(method, data) {
  var auth_method = this.allow_auth_methods[method];

  if (auth_method) {
    var options = auth_method.options;
    var authorize = auth_method.authorize;
    return authorize(data, options);
  }

  return false;
}

Socks5Server.prototype._connect = function(data, callback) {
  var callback = once(callback);
  var addrtype = data[3];

  var host = null;
  var port = null;

  switch (addrtype) {
    case ADDRTYPE.IP_V4:
      host = util.format('%s.%s.%s.%s', data[4], data[5], data[6], data[7]);
      port = data.readUInt16BE(8);
      break;
    case ADDRTYPE.DOMAINNAME:
      var domainLen = data[4];
      host = data.toString('utf8', 5, domainLen + 5);
      port = data.readUInt16BE(domainLen + 5);
      break;
    case ADDRTYPE.IP_V6:
      host = data.slice(4, 20);
      port = data.readUInt16BE(20);
      break;
    default:
      return callback({
        code: REQUEST_STATUS.ADDRTYPE_NOT_SUPPORTED
      });
      break;
  }

  debug('connecting:', valueToKey(ADDRTYPE, addrtype), host, port);

  if (host && port) {
    var remote = net.createConnection(port, host);
    remote.on('connect', function() {
      callback(null, remote);
    });
    remote.on('error', callback);
  } else {
    callback({
      code: REQUEST_STATUS.SERVER_FAILURE
    })
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
  var version = data[0];
  var command = data[1];

  if (version !== VERSION) {
    return callback({
      code: REQUEST_STATUS.CONNECTION_NOT_ALLOWED
    });
  }

  switch (command) {
    case COMMAND.CONNECT:
      this._connect(data, callback);
      break;
    // case COMMAND.BIND:
    //   break;
    // case COMMAND.UDP:
    //   break;
    default:
      return callback({
        code: REQUEST_STATUS.COMMAND_NOT_SUPPORTED
      });
  }
}

Socks5Server.prototype.listen = function() {
  var args = slice.call(arguments);
  debug('listen', args);
  this.server.listen.apply(this.server, args);
};

module.exports = Socks5Server;
