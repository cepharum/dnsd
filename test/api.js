#!/usr/bin/env node
//
// Copyright 2012 Iris Couch, all rights reserved.
//
// Test DNS messages

"use strict";

const File = require( "fs" );

const { test } = require( "tap" );

const { DNSMessage } = require( "../message" );
const API = require( "../index" );
const DATA = __dirname + "/../_test_data";

test( "Message API", function( t ) {
	t.type( DNSMessage, "function", "Message is a function (constructor)" );
	t.throws( function() { new DNSMessage; }, "Message requires a data buffer" );

	t.type( API.decode, "function", "decode function in the API" );
	t.type( API.encode, "function", "encode function in the API" );

	t.throws( function() { API.decode(); }, "Parse function needs a data buffer" );

	t.end();
} );

test( "Parse a valid query", function( t ) {
	const data = File.readFileSync( DATA + "/www.company.example-query" );
	let msg = new DNSMessage( data );

	t.ok( msg, "Parsed a message with the object API" );

	msg = API.decode( data );
	t.ok( msg, "Parsed a message with the decode API" );

	t.end();
} );

test( "Parse a valid response", function( t ) {
	const data = File.readFileSync( DATA + "/www.company.example-response" );
	let msg = new DNSMessage( data );

	t.ok( msg, "Parsed a message with the object API" );

	msg = API.decode( data );
	t.ok( msg, "Parsed a message with the decode API" );

	t.end();
} );
