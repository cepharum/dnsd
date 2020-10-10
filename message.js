// Copyright 2012 Iris Couch, all rights reserved.
//
// Test displaying DNS records

"use strict";

const Util = require( "util" );

const Parse = require( "./decode" );
const { Encoder } = require( "./encode" );
const { typeToLabel, classToLabel } = require( "./constants" );

const SECTIONS = [ "question", "answer", "authority", "additional" ];

// A DNS message.  This is an easy-to-understand object representation of
// standard DNS queries and responses.
//
// Attributes:
// * id                  - a number representing the unique query ID
// * type                - "request" or "response"
// * response            - Number (server response code)
// * opcode              - "query", "iquery", "status", "unassigned", "notify", "update"
// * authoritative       - Boolean
// * truncated           - Boolean
// * recursionDesired   - Boolean
// * recursionAvailable - Boolean
// * authenticated       - Boolean
// * checkingDisabled   - Boolean
//
// Optional attributes:
// * question (optional) - Array of the question section
// * answer (optional) - Array of the answer section
// * authority (optional) - Array of the authority section
// * additional (optional) - Array of the additional section
//
// Methods:
// * toString() - return a human-readable representation of this message
// * toJSON() - Return a JSON-friendly represenation of this message
// * toBinary() - Return a buffer of the encoded message

/**
 * Implements representation of a single DNS message.
 *
 * @property {number} id a number representing the unique query ID
 * @property {string} type "request" or "response"
 * @property {number} response response code
 * @property {string} opcode one out of "query", "iquery", "status", "unassigned", "notify", "update"
 * @property {boolean} authoritative indicates if message is an authoritative answer
 * @property {boolean} truncated indicates if message has been truncated due to oversize
 * @property {boolean} recursionDesired indicates query is asking for recursive processing
 * @property {boolean} recursionAvailable indicates whether service is supporting recursive processing of queries
 * @property {boolean} authenticated marks response message to be authenticated by server
 * @property {boolean} checkingDisabled indicates in a request message that client is accepting non-authenticated data in response
 * @property {DNSRecord[]} question records in question section
 * @property {DNSRecord[]} answer records in answer section
 * @property {DNSRecord[]} authority records in authority section
 * @property {DNSRecord[]} additional records in additional section
 */
class DNSMessage {
	/**
	 * @param {Buffer|object} body sequence of octets describing DNS message in wire format or some object similar to DNSMessage to load properties from
	 */
	constructor( body ) {
		this.id = null;
		this.type = null;
		this.responseCode = null;
		this.opcode = null;
		this.authoritative = null;
		this.truncated = null;
		this.recursionDesired = null;
		this.recursionAvailable = null;
		this.authenticated = null;
		this.checkingDisabled = null;

		if ( Buffer.isBuffer( body ) ) {
			this.parse( body );
		} else if ( body && typeof body === "object" ) {
			Object.assign( this, body );

			for ( const section of SECTIONS ) {
				const records = this[section];

				if ( Array.isArray( records ) )
					records.forEach( ( record, i ) => {
						records[i] = new DNSRecord( record );
					} );
			}
		} else {
			throw new Error( "DNSMessage must be created with raw buffer or object describing message content" );
		}

		// EDNS processing. For now, just remove those records.
		for ( const section of SECTIONS ) {
			if ( this[section] ) {
				this[section] = this[section].filter( record => !record.edns );

				if ( this[section].length === 0 )
					delete this[section];
			}
		}
	}

	/**
	 * Decodes whole DNS message from sequence of octets.
	 *
	 * @param {Buffer} body sequence of octets describing DNS message in wire format
	 * @returns {void}
	 */
	parse( body ) {
		this.id = Parse.id( body );
		this.type = Parse.qr( body ) === 0 ? "request" : "response";

		this.responseCode = Parse.rcode( body );

		const opcodeNames = [ "query", "iquery", "status", null, "notify", "update" ];
		const opcode = Parse.opcode( body );
		this.opcode = opcodeNames[opcode] || null;

		this.authoritative = Boolean( Parse.aa( body ) );
		this.truncated = Boolean( Parse.tc( body ) );
		this.recursionDesired = Boolean( Parse.rd( body ) );
		this.recursionAvailable = Boolean( Parse.ra( body ) );
		this.authenticated = Boolean( Parse.ad( body ) );
		this.checkingDisabled = Boolean( Parse.cd( body ) );

		const sectionsCache = Parse.sections( body );

		for ( const section of SECTIONS ) {
			const count = Parse.recordCount( body, section );
			if ( count ) {
				this[section] = [];

				for ( let i = 0; i < count; i++ )
					this[section].push( new DNSRecord( body, section, i, sectionsCache ) );
			}
		}
	}

	/**
	 * Serializes DNS message into sequence of octets describing it in wire format.
	 *
	 * @returns {Buffer} sequence of octets describing DNS message in wire format
	 */
	toBinary() {
		return new Encoder().message( this ).toBinary();
	}

	/**
	 * Renders string containing some essential information on DNS message.
	 *
	 * @returns {string} description of current DNS message
	 */
	toString() {
		const info = [
			Util.format( "ID                 : %d", this.id ),
			Util.format( "Type               : %s", this.type ),
			Util.format( "Opcode             : %s", this.opcode ),
			Util.format( "Authoritative      : %s", this.authoritative ),
			Util.format( "Truncated          : %s", this.truncated ),
			Util.format( "Recursion Desired  : %s", this.recursionDesired ),
			Util.format( "Recursion Available: %s", this.recursionAvailable ),
			Util.format( "Response Code      : %d", this.responseCode ),
		];

		SECTIONS.forEach( section => {
			if ( this[section] ) {
				info.push( Util.format( ";; %s SECTION:", section.toUpperCase() ) );

				this[section].forEach( record => {
					info.push( record.toString() );
				} );
			}
		} );

		return info.join( "\n" );
	}
}


/**
 * Represents an individual record in a DNS message.
 *
 * @property {string} name domain name this record is applying to
 * @property {string} type type of resource record ('A', 'NS', 'CNAME', etc. or 'Unknown')
 * @property {string} class network class of resource record ('IN', 'None' 'Unknown')
 * @property {number} ttl time to live, number of seconds for caching this record
 * @property {?(object|string|Array)} data record data in type-specific format, null if not applicable
 */
class DNSRecord {
	/**
	 * @param {Buffer|object} body sequence of octets describing DNS record in wire format or data of DNS record extracted before
	 * @param {string} sectionName name of DNS message section this record is associated with
	 * @param {number} recordNum record's index into seleted section's set of records
	 * @param {ParsedSectionsData} sectionsCache previously parsed information on records per section
	 */
	constructor( body, sectionName, recordNum, sectionsCache ) {
		this.name = null;
		this.type = null;
		this.class = null;

		if ( Buffer.isBuffer( body ) )
			this.parse( body, sectionName, recordNum, sectionsCache || body );
		else if ( typeof body === "object" )
			Object.keys( body ).forEach( key => { this[key] = body[key]; } );
		else
			throw new Error( "Must provide a buffer or object argument with message contents" );
	}

	/**
	 * Extracts information on single DNS record from provided buffer.
	 *
	 * @param {Buffer} body sequence of octets describing DNS record in wire format
	 * @param {string} sectionName name of message section this record belongs to
	 * @param {number} recordNum index of record to decode
	 * @param {Buffer|ParsedSectionsData} sections sequence of octets describing full DNS message or previously extracted sections data
	 * @returns {void}
	 */
	parse( body, sectionName, recordNum, sections ) {
		this.name = Parse.recordName( sections, sectionName, recordNum );

		const type = Parse.recordType( sections, sectionName, recordNum );

		this.type = typeToLabel( type );
		if ( ! this.type )
			throw new Error( "Record " + recordNum + ' in section "' + sectionName + '" has unknown type: ' + type );

		if ( sectionName === "additional" && this.type === "OPT" && this.name === "" ) {
			// EDNS record
			this.edns = true;
			delete this.name;
			delete this.class;
		} else {
			// Normal record
			this.class = classToLabel( Parse.recordClass( sections, sectionName, recordNum ) );
			if ( !this.class )
				throw new Error( "Record " + recordNum + ' in section "' + sectionName + '" has unknown class: ' + type );

			if ( sectionName === "question" )
				return;

			this.ttl = Parse.recordTtl( sections, sectionName, recordNum );
		}

		const rdata = Parse.recordData( sections, sectionName, recordNum );

		switch ( this.kind() ) {
			case "IN A" :
				if ( rdata.length !== 4 )
					throw new Error( "Bad IN A data: " + JSON.stringify( this ) );
				this.data = renderIPv4( rdata );
				break;

			case "IN AAAA" :
				if ( rdata.length !== 16 )
					throw new Error( "Bad IN AAAA data: " + JSON.stringify( this ) );
				this.data = renderIPv6( rdata );
				break;

			case "IN NS" :
			case "IN CNAME" :
			case "IN PTR" :
				this.data = Parse.uncompress( body, rdata );
				break;

			case "IN TXT" :
				this.data = Parse.txt( body, rdata );
				if ( this.data.length === 0 )
					this.data = "";
				else if ( this.data.length === 1 )
					this.data = this.data[0];
				break;

			case "IN MX" :
				this.data = Parse.mx( body, rdata );
				break;

			case "IN SRV" :
				this.data = Parse.srv( body, rdata );
				break;

			case "IN SOA" :
				this.data = Parse.soa( body, rdata );
				this.data.rname = this.data.rname.replace( /\./, "@" );
				break;

			case "IN DS" :
				this.data = {
					key_tag: ( rdata[0] << 8 ) + rdata[1],                      // eslint-disable-line camelcase
					algorithm: rdata[2],
					digest_type: rdata[3],                                      // eslint-disable-line camelcase
					digest: rdata.slice( 4 ).toJSON(), // Convert to a list of numbers.
				};
				break;

			case "NONE A" :
				this.data = [];
				break;

			case "IN OPT" :
				this.data = rdata;
				break;

			default :
				throw new Error( "Unknown record " + this.kind() + ": " + JSON.stringify( this ) );
		}
	}

	/**
	 * Renders identifier on current kind of resource record.
	 *
	 * @returns {string} string combining class and type of resource record
	 */
	kind() {
		return this.edns ? "IN OPT" : this.class + " " + this.type;
	}

	/**
	 * Renders current record as string e.g. for dumping/logging.
	 *
	 * @returns {string} rendered string describing current record
	 */
	toString() {
		const { data } = this;

		return [
			leftPad( 23, this.name ),
			leftPad( 7, this.ttl || "" ),
			leftPad( 7, this.class ),
			leftPad( 7, this.type ),
			this.type === "MX" && data ? leftPad( 3, data[0] ) + " " + data[1] : Buffer.isBuffer( data ) ? data.toString( "hex" ) : data || "",
		].join( " " );
	}
}


/**
 * Prepends provided string with additional whitespace to ensure given minimum
 * length.
 *
 * @param {number} minimumLength minimum length of resulting string
 * @param {*} string value to be represented as string
 * @returns {string} provided value represented as string extended to desired minimum length with SPC
 */
function leftPad( minimumLength, string ) {
	const asString = String( string );
	const missing = minimumLength - asString.length;

	return missing > 0 ? new Array( missing ).fill( " " ).join( "" ) + asString : asString;
}

/**
 * Renders binary encoded IPv4 address in CIDR notation.
 *
 * @param {Buffer} octets binary encoded IPv4 address as sequence of four octets
 * @returns {string} encoded IPv4 address in CIDR notation
 */
function renderIPv4( octets ) {
	return Array.prototype.slice.call( octets, 0, 4 ).join( "." );
}

/**
 * Renders binary encoded IPv6 address in related CIDR notation.
 *
 * @param {Buffer} buf binary encoded IPv6 address as sequence of four octets
 * @returns {string} encoded IPv6 address in CIDR notation
 */
function renderIPv6( buf ) {
	return buf.toString( "hex" ).replace( /(....)/g, "$1:" ).replace( /:$/, "" );
}

exports.DNSMessage = DNSMessage;
exports.DNSRecord = DNSRecord;
