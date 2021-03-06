# dnsd: DNS encoder, decoder, and server

*dnsd* is a Node.js package for working with DNS. It converts binary DNS messages to and from convenient JavaScript objects; and it provides a server API, for running a custom name server.

> This module is a fork of dnsd originally developed for Iris Couch. We've basically improved the code and started adding support for EDNS. Currently, we are using it for dynamic exposure of services in a Docker swarm. 

*dnsd* is available as an npm module.

    $ npm install dnsd

## Example: Running a server

This simple DNS server responds with an "A" (address) record of `1.2.3.4` for every request.

```javascript
const dnsd = require( "dnsd" );

dnsd.createServer( ( req, res ) => {
    res.end( "1.2.3.4" );
}, {
    // provide custom defaults here
    ttl: 3600,
} )
    .zone( "example" )
    .listen( 5353, "127.0.0.1" )
    .once( "listening", () => {
        console.log( "Server is running at 127.0.0.1:5353" );
    } );
```

Now test your server:

    $ dig @localhost -p 5353 foo.example A

    ; <<>> DiG 9.8.1-P1 <<>> @localhost -p 5353 foo.example A
    ; (1 server found)
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 27955
    ;; flags: qr rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
    ;; WARNING: recursion requested but not available

    ;; QUESTION SECTION:
    ;foo.example.			IN	A

    ;; ANSWER SECTION:
    foo.example.		3600	IN	A	1.2.3.4

    ;; Query time: 1 msec
    ;; SERVER: 127.0.0.1#5353(127.0.0.1)
    ;; WHEN: Wed Aug  8 05:10:40 2012
    ;; MSG SIZE  rcvd: 45

This example logs all requests. For address (A) queries, it returns two records, with a random TTL, and the final octet of the IP address is the length of the hostname queried.

```javascript
const dnsd = require( "dnsd" );

dnsd.createServer(handler)
    .zone("example.com", "ns1.example.com", "us@example.com", "now", "2h", "30m", "2w", "10m" )
    .listen( 5353, "127.0.0.1" );

function handler(req, res) {
    const { remoteAddress, remotePort, type } = req.connection;

    console.log( "%s:%s/%s %j", remoteAddress, remotePort, type, req );
    
    const question = res.question[0];
    const hostname = question.name;
    const length = hostname.length;
    const ttl = Math.floor( Math.random() * 3600 );

    if ( question.type === "A" ) {
        res.answer.push( { name:hostname, type:"A", data:"1.1.1." + length, ttl } );
        res.answer.push( { name:hostname, type:"A", data:"2.2.2." + length, ttl } );
    }

    res.end()
}
```

Test the SOA response:

    $ dig @localhost -p 5353 example.com soa

    ; <<>> DiG 9.8.1-P1 <<>> @localhost -p 5353 example.com soa
    ; (1 server found)
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 30176
    ;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
    ;; WARNING: recursion requested but not available

    ;; QUESTION SECTION:
    ;example.com.			IN	SOA

    ;; ANSWER SECTION:
    example.com.		600	IN	SOA	ns1.example.com. us.example.com. 1344403648 7200 1800 1209600 600

    ;; Query time: 5 msec
    ;; SERVER: 127.0.0.1#5353(127.0.0.1)
    ;; WHEN: Wed Aug  8 05:27:32 2012
    ;; MSG SIZE  rcvd: 72

And test the address (A) response:

    $ dig @localhost -p 5353 example.com a

    ; <<>> DiG 9.8.1-P1 <<>> @localhost -p 5353 example.com a
    ; (1 server found)
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 19419
    ;; flags: qr aa rd; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0
    ;; WARNING: recursion requested but not available

    ;; QUESTION SECTION:
    ;example.com.			IN	A

    ;; ANSWER SECTION:
    example.com.		1222	IN	A	1.1.1.11
    example.com.		1222	IN	A	2.2.2.11

    ;; Query time: 1 msec
    ;; SERVER: 127.0.0.1#5353(127.0.0.1)
    ;; WHEN: Wed Aug  8 05:27:34 2012
    ;; MSG SIZE  rcvd: 61

Server output for these queries:

    Server running at 127.0.0.1:5353
    127.0.0.1:34427/udp4 {"id":30176,"type":"request","responseCode":0,"opcode":"query","authoritative":false,"truncated":false,"recursionDesired":true,"recursionAvailable":false,"authenticated":false,"checkingDisabled":false,"question":[{"name":"example.com","type":"SOA","class":"IN"}]}
    127.0.0.1:59596/udp4 {"id":19419,"type":"request","responseCode":0,"opcode":"query","authoritative":false,"truncated":false,"recursionDesired":true,"recursionAvailable":false,"authenticated":false,"checkingDisabled":false,"question":[{"name":"example.com","type":"A","class":"IN"}]}


## Example: MX Records

This is an example if you need to route your mail server with an MX record.

```javascript
// Example MX response with dnsd
//
// To test:
// 1. Run this program
// 2. dig @localhost -p 5353 example.com mx
 
const dnsd = require( "dnsd" );
 
dnsd.createServer( handler )
    .zone( "example.com", "ns1.example.com", "us@example.com", "now", "2h", "30m", "2w", "10m" )
    .listen( 5353, "127.0.0.1" );
 
function handler(req, res) {
    const question = res.question && res.question[0]
    
    if ( question.type === "MX" ) {
        console.log( "MX lookup for domain: %s", question.name );
        
        res.answer.push( { name:question.name, type:"MX", data:{ weight: 10, name: "mail.example.com" } } );
        res.answer.push( { name:question.name, type:"MX", data:{ weight: 20, name: "mail.backupexample.com" } } );
    }
    
    return res.end();
}
```

The MX data attribute needs to be an Array to work properly, the first value is the priority, the second is the server.
This server name must be a domain string and not an IP address. Make sure you have an A record or CNAME setup for this.

See http://support.google.com/a/bin/answer.py?hl=en&answer=140034 for more info on MX records and configuration.



## Example: Parse a message

```javascript
const fs = require("fs")
const dnsd = require("dnsd")

const msg_file = require.resolve( "dnsd/_test_data/registry.npmjs.org-response" );
const msg_data = fs.readFileSync( msg_file );
const message = dnsd.decode( msg_data );

console.dir( message );
```

Output

```javascript
{ 
    id: 34233,
    type: "response",
    responseCode: 0,
    opcode: "query",
    authoritative: false,
    truncated: false,
    recursionDesired: true,
    recursionAvailable: true,
    authenticated: false,
    checkingDisabled: false,
    question: [ { name: "registry.npmjs.org", type: "A", class: "IN" } ],
    answer: [ 
        { 
            name: "registry.npmjs.org",
            type: "CNAME",
            class: "IN",
            ttl: 85,
            data: "isaacs.iriscouch.net",
        }, { 
            name: "isaacs.iriscouch.net",
            type: "CNAME",
            class: "IN",
            ttl: 2821,
            data: "ec2-23-23-147-24.compute-1.amazonaws.com",
         }, { 
            name: "ec2-23-23-147-24.compute-1.amazonaws.com",
            type: "A",
            class: "IN",
            ttl: 356336,
            data: "23.23.147.24",
         }, 
    ],
}
```

## Example: Encode a message

```javascript
const dnsd = require("dnsd")

const questions = [ { name: "example.com", class: "IN", type: "TXT" } ];
const message = { 
    type: "query", 
    id: 123, 
    opcode: "query", 
    recursionDesired: true, 
    question: questions
};
const msg_data = dnsd.encode( message );

console.log( "Encoded = %j", Array.prototype.slice.apply( msg_data ) );

message = dnsd.decode( msg_data );

console.log( "Round trip:" );
console.dir( message );
```

Output:

```javascript
Encoded = [0,123,1,0,0,1,0,0,0,0,0,0,7,101,120,97,109,112,108,101,3,99,111,109,0,0,16,0,1]
Round trip:
{ id: 123,
  type: 'request',
  responseCode: 0,
  opcode: 'query',
  authoritative: false,
  truncated: false,
  recursionDesired: true,
  recursionAvailable: false,
  authenticated: false,
  checkingDisabled: false,
  question: [ { name: 'example.com', type: 'TXT', class: 'IN' } ] }
```

## Convenience Support

* You can pass a value to `res.end()`, with special handling depending on type:
  * Array: those values will be added to the `res.answer` section.
  * Object: that object will be sent as a response (`res` is unused).
  * String: the response will add an anser `A` record with your value as the IP address.
* Automatically respond to `SOA` queries with the `SOA` record.
* Responses to an `A` query with no answers will add the `SOA` record to the response.
* If the response records are missing a TTL, use the one from the `.zone()` definition (the `SOA` record)


## Tests

This code is tested with [node-tap][tap].

    $ tap test
    ok test/api.js ........................................ 10/10
    ok test/convenience.js ................................ 22/22
    ok test/message.js .................................. 176/176
    ok test/print.js ...................................... 10/10
    ok test/server.js ..................................... 35/35
    total ............................................... 253/253

    ok

## License

Apache 2.0

See the [Apache 2.0 license](dnsd/blob/master/LICENSE).

[tap]: https://github.com/isaacs/node-tap
[def]: https://github.com/iriscouch/defaultable
