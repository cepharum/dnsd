// Copyright 2012 Iris Couch, all rights reserved.
//
// The dnsd package API

"use strict";

const { DNSMessage } = require( "./message" );
const createServer = require( "./server" );

module.exports = {
	decode,
	encode,
	createServer,
};

/**
 * Parses DNS message from a sequence of octets.
 *
 * @param {Buffer} packet wire formatted data
 * @returns {DNSMessage} parsed message
 */
function decode( packet ) {
	return new DNSMessage( packet );
}

/**
 * Serializes provided message into wire-formatted sequence of octets.
 *
 * @param {DNSMessage|Buffer|object} message message to serialize
 * @returns {Buffer} serialized message
 */
function encode( message ) {
	return ( message instanceof DNSMessage ? message : new DNSMessage( message ) ).toBinary();
}
