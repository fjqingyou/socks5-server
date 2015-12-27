var Socks5Server = require('../').Socks5Server;
var AUTH_METHODS = require('../').AUTH_METHODS;

var server = new Socks5Server();

// server.registerAuth(AUTH_METHOS.NOAUTH, auth.noauth);
server.registerAuth(AUTH_METHODS.USERNAME_PASSWORD, {
  username: 'username',
  password: 'password'
});

server.listen(1080, function() {
  address = server.server.address();
  console.log("server on %j", address);
});
