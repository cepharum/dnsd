#!/usr/bin/env node
//
// Copyright 2012 Iris Couch, all rights reserved.
//
// Test displaying DNS records

"use strict";

const File = require( "fs" );
const { test } = require( "tap" );
const util = require( "util" );

const { DNSMessage } = require( "../message" );

test( "Display a message", function( t ) {
	const file = "oreilly.com-response";
	File.readFile( __dirname + "/../_test_data/" + file, function( er, data ) {
		if ( er )
			throw er;

		const msg = new DNSMessage( data ),
			str = util.format( "%s", msg );

		t.type( str, "string", "Message can encode" );

		const obj = JSON.parse( util.format( "%j", msg ) );

		t.equal( obj.id, 45753, "JSON round-trip: id" );
		t.equal( obj.type, "response", "JSON round-trip: type" );
		t.equal( obj.opcode, "query", "JSON round-trip: opcode" );
		t.equal( obj.authoritative, true, "JSON round-trip: authoritative" );
		t.equal( obj.truncated, false, "JSON round-trip: truncated" );
		t.equal( obj.recursionDesired, true, "JSON round-trip: recursionDesired" );
		t.equal( obj.recursionAvailable, true, "JSON round-trip: recursionAvailable" );
		t.equal( obj.responseCode, 0, "JSON round-trip: responseCode" );

		t.end();
	} );
} );
