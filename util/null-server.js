#!/usr/bin/env node

var named = require('../named')

var port = +(process.argv[2] || 5321)
named.createServer(function(req, res) {
  console.log('%s:%s/%s %j', req.connection.remoteAddress, req.connection.remotePort, req.connection.type, req)
  req.connection.end()
}).listen(port)
  .zone('oreilly.com', 'ns1.iriscouch.net', 'us@iriscouch.com', 'now', 86400, 7200, 1800, 1209600, 3600)

console.log('Listening on port %d', port)
