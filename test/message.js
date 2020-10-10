// Copyright 2012 Iris Couch, all rights reserved.
//
// Test DNS message parsing

"use strict";

const File = require( "fs" );
const { test } = require( "tap" );

const { decode, encode } = require( "../" );

test( "Parse all known messages", function( t ) {
	const files = [
		"dynamic-update", "oreilly.com-query", "oreilly.com-response",
		"www.company.example-query", "www.company.example-response",
		"www.microsoft.com-query", "www.microsoft.com-response", "edns-query",
	];

	files.forEach( function( name ) {
		const data = packet( name );
		let msg = null;

		t.doesNotThrow( function() { msg = decode( data ); }, "No errors parsing " + name );

		t.ok( msg, "Parse packet: " + name );
		t.ok( msg.id, "Packet id: " + name );
		// console.log('%s:\n%s\n\n', name, util.inspect(msg, 0, 10))
	} );

	t.end();
} );

test( "Parse invalid messages", function( t ) {
	const data = Buffer.from( "My name is Jason and I am awesome." );
	t.throws( function() { decode( data ); }, "Exception parsing random data" );
	t.end();
} );

test( "Optimized parsing", function( t ) {
	const data = packet( "oreilly.com-response" );
	data.__decoded = 0;

	decode( data );
	t.equal( data.__decoded, 1, "Parsing only runs once (after that, it is memoized)" );
	t.end();
} );

test( "Message attributes", function( t ) {
	let msg;

	msg = decode( packet( "oreilly.com-response" ) );
	t.equal( msg.type, "response", "DNS response" );
	t.equal( msg.opcode, "query", "DNS opcode" );
	t.equal( msg.authoritative, true, "Authoritative message" );
	t.equal( msg.truncated, false, "Non-truncated message" );
	t.equal( msg.recursionDesired, true, "Recursion-desired in response" );
	t.equal( msg.responseCode, 0, "Successful response" );

	msg = decode( packet( "oreilly.com-query" ) );
	t.equal( msg.type, "request", "DNS request" );
	t.equal( msg.authoritative, false, "Non-authoritative request" );
	t.equal( msg.recursionDesired, true, "Recursion-desired in request" );

	msg = decode( packet( "dynamic-update" ) );
	t.equal( msg.opcode, "update", "DNS update opcode" );

	msg = decode( packet( "www.microsoft.com-response" ) );
	t.equal( msg.recursionDesired, false, "No recursion desired" );
	t.equal( msg.recursionAvailable, false, "No recursion available" );

	t.end();
} );

test( "Message sections", function( t ) {
	let msg;

	msg = decode( packet( "www.microsoft.com-query" ) );
	t.type( msg.question, "Array", "Parse question section" );
	t.type( msg.answer, "Array", "Always parse answer section" );
	t.equal( msg.answer.length, 0, "Empty answer section" );
	t.type( msg.authority, "Array", "Always parse authority section" );
	t.equal( msg.authority.length, 0, "Empty authority section" );
	t.type( msg.additional, "Array", "Always parse additional section" );
	t.equal( msg.additional.length, 0, "Empty additional section" );

	msg = decode( packet( "oreilly.com-response" ) );
	t.type( msg.whatever, "undefined", 'No "whatever" section' );
	t.type( msg.question, "Array", "Parse question section" );
	t.type( msg.answer, "Array", "Parse answer section" );
	t.type( msg.authority, "Array", "Parse authority section" );
	t.type( msg.additional, "Array", "Parse additional section" );

	t.end();
} );

test( "Message records", function( t ) {
	let msg;

	msg = decode( packet( "oreilly.com-response" ) );
	t.equal( msg.question.length, 1, "Enumerate question records" );
	t.equal( msg.answer.length, 2, "Enumerate answer records" );
	t.equal( msg.authority.length, 3, "Enumerate authority records" );
	t.equal( msg.additional.length, 5, "Enumerate additional records" );

	msg.question.forEach( function( rec, i ) { t.type( rec, "object", "Question record is object: " + i ); } );
	msg.answer.forEach( function( rec, i ) { t.type( rec, "object", "Answer record is object: " + i ); } );
	msg.authority.forEach( function( rec, i ) { t.type( rec, "object", "Authority record is object: " + i ); } );
	msg.additional.forEach( function( rec, i ) { t.type( rec, "object", "Additional record is object: " + i ); } );

	msg = decode( packet( "www.microsoft.com-response" ) );
	t.equal( msg.question[0].name, "www.microsoft.com.nsatc.net", "Question name" );
	t.equal( msg.answer[0].name, "www.microsoft.com.nsatc.net", "Answer name" );
	t.equal( msg.authority[0].name, "nsatc.net" , "1st authority name" );
	t.equal( msg.authority[1].name, "nsatc.net" , "2nd authority name" );
	t.equal( msg.authority[2].name, "nsatc.net" , "3rd authority name" );
	t.equal( msg.authority[3].name, "nsatc.net" , "4th authority name" );
	t.equal( msg.additional[0].name, "j.ns.nsatc.net" , "1st additional name" );
	t.equal( msg.additional[1].name, "k.ns.nsatc.net" , "2nd additional name" );
	t.equal( msg.additional[2].name, "us-ca-6.ns.nsatc.net" , "3rd additional name" );
	t.equal( msg.additional[3].name, "l.ns.nsatc.net" , "4th additional name" );

	msg = decode( packet( "oreilly.com-response" ) );
	t.type( msg.question[0].ttl, "undefined", "No TTL for question record" );
	t.equal( msg.answer[0].ttl, 3600 , "1st answer ttl" );
	t.equal( msg.answer[1].ttl, 3600 , "2nd answer ttl" );
	t.equal( msg.authority[0].ttl, 21600, "1st authority ttl" );
	t.equal( msg.authority[1].ttl, 21600, "2nd authority ttl" );
	t.equal( msg.authority[2].ttl, 21600, "3rd authority ttl" );
	t.equal( msg.additional[0].ttl, 21600, "1st additional ttl" );
	t.equal( msg.additional[1].ttl, 21600, "2nd additional ttl" );
	t.equal( msg.additional[2].ttl, 21600, "3rd additional ttl" );
	t.equal( msg.additional[3].ttl, 32537, "4th additional ttl" );
	t.equal( msg.additional[4].ttl, 32537, "5th additional ttl" );

	msg.question.forEach( function( rr, i ) { t.equal( rr.class, "IN", "Question class is IN: " + i ); } );
	msg.answer.forEach( function( rr, i ) { t.equal( rr.class, "IN", "Answer class is IN: " + i ); } );
	msg.authority.forEach( function( rr, i ) { t.equal( rr.class, "IN", "Authority class is IN: " + i ); } );
	msg.additional.forEach( function( rr, i ) { t.equal( rr.class, "IN", "Additional class is IN: " + i ); } );

	msg = decode( packet( "dynamic-update" ) );
	t.equal( msg.question[0].type, "SOA", "SOA question class" );
	t.equal( msg.answer[0].class, "NONE", "NONE answer class" );

	msg = decode( packet( "oreilly.com-response" ) );
	t.equal( msg.question[0].type, "MX", "Question type" );
	t.equal( msg.answer[0].type, "MX", "1st answer type" );
	t.equal( msg.answer[1].type, "MX", "2nd answer type" );
	t.equal( msg.authority[0].type, "NS", "1st authority type" );
	t.equal( msg.authority[1].type, "NS", "2nd authority type" );
	t.equal( msg.authority[2].type, "NS", "3rd authority type" );
	t.equal( msg.additional[0].type, "A" , "1st additional type" );
	t.equal( msg.additional[1].type, "A" , "2nd additional type" );
	t.equal( msg.additional[1].type, "A" , "3rd additional type" );
	t.equal( msg.additional[2].type, "A" , "4th additional type" );
	t.equal( msg.additional[3].type, "A" , "5th additional type" );

	t.type( msg.question[0].data, "undefined", "No question data" );
	t.same( msg.answer[0].data, { weight: 20, name: "smtp1.oreilly.com" }, "1st answer data" );
	t.same( msg.answer[1].data, { weight: 20, name: "smtp2.oreilly.com" }, "2nd answer data" );
	t.equal( msg.authority[0].data, "ns1.sonic.net" , "1st authority data" );
	t.equal( msg.authority[1].data, "ns2.sonic.net" , "2nd authority data" );
	t.equal( msg.authority[2].data, "ns.oreilly.com", "3rd authority data" );
	t.equal( msg.additional[0].data, "209.204.146.22", "1st additional data" );
	t.equal( msg.additional[1].data, "209.58.173.22" , "2nd additional data" );
	t.equal( msg.additional[2].data, "209.204.146.21", "3rd additional data" );
	t.equal( msg.additional[3].data, "208.201.224.11", "4th additional data" );
	t.equal( msg.additional[4].data, "208.201.224.33", "5th additional data" );

	t.end();
} );

test( "Convenient text records", function( t ) {
	t.plan( 9 );

	const msg = decode( packet( "txt-response" ) );
	msg.answer.forEach( function( rec, i ) {
		t.equal( rec.type, "TXT", "Parse text record: " + i );
		t.type( rec.data, "string", "Single text records become a string: " + i );
	} );

	// Convert to an array and see if it persists correctly.
	const data = msg.answer[0].data;
	msg.answer[0].data = [ data, "An extra string" ];

	const body = msg.toBinary()
		, msg2 = decode( body );

	t.type( msg2.answer[1].data, "string", "Single text record still a string" );
	t.type( msg2.answer[0].data, "Array" , "Multiple text records are an array" );
	t.equal( msg2.answer[0].data.length, 2, "All text data accounted for" );

	t.end();
} );

test( "Encoding messages", function( t ) {
	const files = [
		"dynamic-update", "oreilly.com-query", "oreilly.com-response", "www.company.example-query",
		"www.company.example-response", "www.microsoft.com-query", "www.microsoft.com-response",
		"iriscouch.com-query", "iriscouch.com-response", "foo.iriscouch.com-query", "foo.iriscouch.com-response",
		"registry.npmjs.org-response", "srv-query", "srv-response", "txt-query", "txt-response",
		"ptr-query", "ptr-response", "aaaa-query", "aaaa-response", "ipv6_ptr-query", "ds-query", "ds-response",
	];

	t.plan( 2 * files.length ); // 3 for each file

	files.forEach( function( file ) {
		const original = packet( file );
		const message = decode( original );
		const encoded = encode( message );

		// Strangely, the SOA response does not completely compress the ".com"
		if ( file === "iriscouch.com-response" )
			t.same( encoded.length, original.length - 3, "decode/encode round-trip: " + file );
		else
			t.same( encoded, original, "decode/encode round-trip: " + file );

		const redecoded = decode( encoded );

		t.same( redecoded, message, "decode/encode/decode round-trip: " + file );
	} );

	t.end();
} );

function packet( name ) {
	return File.readFileSync( __dirname + "/../_test_data/" + name );
}
