// Copyright 2012 Iris Couch, all rights reserved.
//
// Parse DNS messages

"use strict";

const Constants = require( "./constants" );


/**
 * Extracts ID from DNS message provided as sequence of octets in wire format.
 *
 * @param {Buffer} msg encoded DNS message
 * @returns {number} extracted ID of DNS message
 */
exports.id = msg => msg.readUInt16BE( 0 );

exports.qr = msg => msg.readUInt8( 2 ) >> 7;
exports.opcode = msg => ( msg.readUInt8( 2 ) >> 3 ) & 0x0f;
exports.aa = msg => ( msg.readUInt8( 2 ) >> 2 ) & 0x01;
exports.tc = msg => ( msg.readUInt8( 2 ) >> 1 ) & 0x01;
exports.rd = msg => msg.readUInt8( 2 ) & 0x01;

exports.ra = msg => msg.readUInt8( 3 ) >> 7;
exports.ad = msg => ( msg.readUInt8( 3 ) >> 5 ) & 0x01;
exports.cd = msg => ( msg.readUInt8( 3 ) >> 4 ) & 0x01;
exports.rcode = msg => msg.readUInt8( 3 ) & 0x0f;

exports.recordName = ( msg, sectionName, offset ) => getRecord( msg, sectionName, offset ).name;
exports.recordClass = ( msg, sectionName, offset ) => getRecord( msg, sectionName, offset ).class;
exports.recordType = ( msg, sectionName, offset ) => getRecord( msg, sectionName, offset ).type;
exports.recordTtl = ( msg, sectionName, offset ) => getRecord( msg, sectionName, offset ).ttl;
exports.recordData = ( msg, sectionName, offset ) => getRecord( msg, sectionName, offset ).data;
exports.recordCount = ( msg, name ) => {
	if ( name === "question" )
		return msg.readUInt16BE( 4 );

	if ( name === "answer" )
		return msg.readUInt16BE( 6 );

	if ( name === "authority" )
		return msg.readUInt16BE( 8 );

	if ( name === "additional" )
		return msg.readUInt16BE( 10 );

	throw new Error( "Unknown section name: " + name );
};

/**
 * Extracts records per section from encoded DNS message.
 *
 * @param {Buffer} msg sequence of octets describing DNS message in wire format
 * @returns {ParsedSectionsData} map of section names into list of records per section
 */
exports.sections = msg => {
	if ( msg.hasOwnProperty( "__decoded" ) ) {
		msg.__decoded++;                                                        // eslint-disable-line no-param-reassign
	}

	const states = [ "question", "answer", "authority", "additional" ];
	const records = {};
	const recordCounts = {
		question: exports.recordCount( msg, "question" ),
		answer: exports.recordCount( msg, "answer" ),
		authority: exports.recordCount( msg, "authority" ),
		additional: exports.recordCount( msg, "additional" ),
	};
	let position = 12; // first byte of the first section


	for ( const stateName of states ) {
		const numRecords = recordCounts[stateName];
		const collector = records[stateName] = new Array( numRecords );

		for ( let i = 0; i < numRecords; i++ ) {
			const record = collector[i] = {};

			const data = compileName( msg, null, position );
			record.name = data.segments.join( "." );
			position += data.length;

			const typeValue = record.type = msg.readUInt16BE( position );
			const classValue = msg.readUInt16BE( position + 2 );
			position += 4;

			if ( stateName !== "question" ) {
				const ttl = msg.readUInt32BE( position );
				const rdataLength = msg.readUInt16BE( position + 4 );

				position += 6;
				record.data = msg.slice( position, position + rdataLength );

				position += rdataLength;

				if ( Constants.type( typeValue ) === "OPT" ) {
					// EDNS
					if ( record.name !== "" )
						throw new Error( `invalid EDNS: name of OPT RR must be empty, but found "${record.name}"` );

					record.udpSize = classValue;

					record.extendedRcode = ttl >> 24;
					record.ednsVersion = ( ttl >> 16 ) & 0xff;
					record.zero = ttl >> 8;

					record.data = Array.prototype.slice.call( record.data );

					continue;
				}

				record.ttl = ttl;
			}

			record.class = classValue;
			record.type = typeValue;
		}
	}

	return records;
};

/**
 * Extracts information from provided record data of a MX RR.
 *
 * @param {Buffer} msg sequence of octets describing full DNS message in wire format
 * @param {Buffer} data part of `msg` describing RDATA of resource record in wire format
 * @returns {MXData} custom data of MX resource record
 */
exports.mx = ( msg, data ) => ( {
	weight: data.readUInt16BE( 0 ),
	name: exports.uncompress( msg, data, 2 ),
} );

/**
 * Extracts information from provided record data of a SRV RR.
 *
 * @param {Buffer} msg sequence of octets describing full DNS message in wire format
 * @param {Buffer} data part of `msg` describing RDATA of resource record in wire format
 * @returns {SRVData} custom data of SRV resource record
 */
exports.srv = ( msg, data ) => ( {
	priority: data.readUInt16BE( 0 ),
	weight: data.readUInt16BE( 2 ),
	port: data.readUInt16BE( 4 ),
	target: exports.uncompress( msg, data, 6 ),
} );

/**
 * Extracts information from provided record data of a SOA RR.
 *
 * @param {Buffer} msg sequence of octets describing full DNS message in wire format
 * @param {Buffer} data part of `msg` describing RDATA of resource record in wire format
 * @returns {SOAData} custom data of SOA resource record
 */
exports.soa = ( msg, data ) => {
	const mname = compileName( msg, data );
	const rname = compileName( msg, data, mname.length );
	const offset = mname.length + rname.length;

	return {
		mname: mname.segments.join( "." ),
		rname: rname.segments.join( "." ),
		serial: data.readUInt32BE( offset ),
		refresh: data.readUInt32BE( offset + 4 ),
		retry: data.readUInt32BE( offset + 8 ),
		expire: data.readUInt32BE( offset + 12 ),
		ttl: data.readUInt32BE( offset + 16 ),
	};
};

/**
 * Extracts data of TXT resource record.
 *
 * @param {Buffer} msg sequence of octets describing full DNS message in wire format
 * @param {Buffer} data part of `msg` describing RDATA of resource record in wire format
 * @returns {string[]} lists segments of ASCII text found in TXT record data
 */
exports.txt = ( msg, data ) => {
	const parts = [];

	for ( let iter = data; iter.length; ) {
		const len = iter.readUInt8( 0 );

		parts.push( iter.slice( 1, 1 + len ).toString( "ascii" ) );

		iter = iter.slice( 1 + len );
	}

	return parts;
};

/**
 * Extracts domain name from DNS message at given offset.
 *
 * @param {Buffer} msg sequence of octets describing full DNS message in wire format
 * @param {Buffer} sub part of `msg` containing name to extract
 * @param {int} offset 0-based index into `sub` (or `msg` if `sub` is omitted) addressing octet to start extraction at
 * @returns {string} extracted domain name
 */
exports.uncompress = ( msg, sub = null, offset = 0 ) => compileName( msg, sub, offset ).segments.join( "." );



/**
 * Extracts variable-length name from provided (slice of a) DNS message handling
 * probably used pointers for compressing DNS message.
 *
 * @see https://tools.ietf.org/html/rfc1035#section-4.1.4
 *
 * @param {Buffer} fullMessage sequence of octets describing whole DNS message in wire format
 * @param {Buffer} slice sequence of octets describing segment of that DNS message
 * @param {int} offset 0-based index into slice (or fullMessage when omitted) name should be extracted from
 * @returns {{segments: [], length: *}} segments of extracted domain name, number of octets occupied by name up to first encountered pointer
 */
function compileName( fullMessage, slice = null, offset = 0 ) {
	if ( typeof offset !== "number" || isNaN( offset ) || offset < 0 || offset > fullMessage.length )
		throw new Error( "Bad offset: " + offset );

	const segments = [];
	const pointersCache = {};
	let buffer = slice || fullMessage;
	let cursor = offset;
	let labelLength = 1;
	let numOctets = 1;
	let metPointer = false;

	while ( labelLength > 0 ) {
		const byte = buffer.readUInt8( cursor++ );

		switch ( byte & 0xc0 ) {
			case 0xc0 : {
				// pointer
				const pointer = ( ( byte & 0x3f ) << 8 ) + buffer.readUInt8( cursor++ );

				if ( pointer >= fullMessage.length ) {
					throw new TypeError( "invalid out-of-bounds pointer" );
				}

				if ( pointersCache[pointer] ) {
					throw new TypeError( "circular pointer references discovered" );
				}

				pointersCache[pointer] = true;

				if ( !metPointer ) {
					numOctets = cursor - offset;
				}

				metPointer = true;

				buffer = fullMessage;
				cursor = pointer;
				break;
			}

			case 0x00 :
				// label
				labelLength = byte & 0x3f;

				if ( labelLength > 0 ) {
					segments.push( buffer.toString( "ascii", cursor, cursor + labelLength ) );

					cursor += labelLength;
				}
				break;

			default :
				throw new Error( `unexpected type of label, maybe data is corrupted` );
		}
	}

	if ( !metPointer ) {
		numOctets = cursor - offset;
	}

	return { segments, length: numOctets };
}

/**
 * Extracts record selected by its containing section of message and its index
 * inside that section from provided DNS message.
 *
 * @param {Buffer|ParsedSectionsData} msg sequence of octets describing full DNS message or previously extracted sections data
 * @param {string} sectionName name of section to extract
 * @param {number} offset index of record in selected section to extract
 * @returns {object} selected record
 */
function getRecord( msg, sectionName, offset ) {
	if ( typeof offset !== "number" || isNaN( offset ) || offset < 0 )
		throw new Error( "Offset must be a natural number" );

	const sections = Buffer.isBuffer( msg ) ? exports.sections( msg ) : msg;

	const records = sections[sectionName];
	if ( !records )
		throw new Error( `No such section: "${sectionName}"` );

	const record = records[offset];
	if ( !record )
		throw new Error( `Bad offset for section "${sectionName}": ${offset}` );

	return record;
}



/**
 * @typedef {object} MXData
 * @property {number} weight weight of MX service in comparison to other MX services defined
 * @property {string} target domain name of host providing MX service
 */

/**
 * @typedef {object} SRVData
 * @property {number} priority service priority
 * @property {number} weight service weight
 * @property {port} port IP port service is listening on
 * @property {string} target domain name of host providing described service
 */

/**
 * @typedef {object} SOAData
 * @property {string} mname domain name of zone
 * @property {string} rname encoded mail address of zone administrator
 * @property {number} serial serial number indicating latest change of zone
 * @property {number} refresh number of seconds for a slave to wait before checking for update of zone again
 * @property {number} retry number of seconds for a slave to wait before trying again after failed transfer of zone
 * @property {number} expire number of seconds for a slave to wait before considering a zone gone while transfers keep failing
 * @property {number} ttl negative TTL for resolvers to wait before querying again in case of general errors in context of zone
 */

/**
 * @typedef {object<string,object[]>} ParsedSectionsData
 */
