// Copyright 2012 Iris Couch, all rights reserved.
//
// Test DNS server

"use strict";

const File = require( "fs" );
const Net = require( "net" );
const dgram = require( "dgram" );

const { test } = require( "tap" );

const API = require( "../index" );

const PORT = 5321;

test( "Server API", function( t ) {
	// The idea is to mimic the http or net server API.
	t.type( API.createServer, "function", "createServer() API call" );
	t.equal( API.createServer.length, 1, "createServer() takes one argument" );

	let server;
	t.doesNotThrow( () => { server = API.createServer(); }, "Create a server" );
	t.type( server.listen, "function", "Server has a .listen() method" );
	t.equal( server.listen.length, 3, "listen() method takes three parameters" );

	t.end();
} );

test( "Network server", function( t ) {
	const server = API.createServer( function( req, res ) {
		console.log( "Req: %j", req );
		console.log( "Res: %j", res );
		res.end();
	} );

	const events = { listening: 0, close: 0, error: 0 };
	let listenCallback = false;

	server.on( "listening", function() { events.listening += 1; } );
	server.on( "close", function() { events.close += 1; } );
	server.on( "error", function() { events.error += 1; } );

	server.listen( PORT, "127.0.0.1", function() { listenCallback = true; } );
	setTimeout( checkInit, 150 );
	setTimeout( checkStop, 200 );

	function checkInit() {
		t.ok( listenCallback, '"listen" callback called' );
		t.equal( events.listening, 1, 'Fired "listening" event' );
		t.equal( events.close, 0, 'No "close" events' );
		t.equal( events.error, 0, 'No "error" events' );

		server.close();
	}

	function checkStop() {
		t.equal( events.close, 1, 'Fired "close" event' );
		t.equal( events.error, 0, 'Still no "error" events' );

		t.end();
	}
} );

test( "Network queries", function( t ) {
	const reqs = {
		"ru.ac.th": { id: 36215, opcode: "update", recursion: false, name: "dynamic-update" },
		"oreilly.com": { id: 45753, opcode: "query" , recursion: true , name: "oreilly.com-query" },
		"www.company.example": { id: 62187, opcode: "query" , recursion: true , name: "www.company.example-query" },
		"www.microsoft.com.nsatc.net": { id: 47096, opcode: "query" , recursion: true , name: "www.microsoft.com-query" },
	};

	let i = 0;
	const server = API.createServer( checkReq );
	server.listen( PORT, "127.0.0.1" );
	server.on( "listening", sendRequests );

	function checkReq( req, res ) {
		t.type( req.question, "Array", "Got a question message" );
		t.equal( req.question.length, 1, "Got exactly one question" );

		const question = req.question[0]
			, name = question.name
			, expected = reqs[name];

		t.ok( expected, "Found expected request: " + name );
		t.equal( req.id, expected.id, "ID match: " + name );
		t.equal( req.opcode, expected.opcode, "Opcode match: " + name );
		t.equal( req.recursionDesired, expected.recursion, "Recursion match: " + name );

		res.end();

		i += 1;
		if ( i === 4 ) {
			server.close();
			t.end();
		}
	}

	function sendRequests() {
		let type = "tcp";
		Object.keys( reqs ).forEach( function( domain ) {
			const data = File.readFileSync( __dirname + "/../_test_data/" + reqs[domain].name );

			if ( type === "udp" ) {
				type = "tcp";
				const sock = dgram.createSocket( "udp4" );
				sock.send( data, 0, data.length, PORT, "127.0.0.1", function() { sock.close(); } );
			} else {
				type = "udp";
				// console.error( "TCP to %d", PORT );
				const sock = Net.connect( { port: PORT }, function() {
					sock.write( Buffer.from( [ data.length >> 8, data.length & 0xff ] ) );
					sock.write( data );
					sock.end();
				} );
			}
		} );
	}
} );
