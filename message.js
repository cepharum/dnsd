// Copyright 2012 Iris Couch, all rights reserved.
//
// Test displaying DNS records

"use strict";

const Util = require( "util" );

const Decode = require( "./decode" );
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
				const records = this[section] = [];

				if ( Array.isArray( records ) )
					records.forEach( ( record, i ) => {
						records[i] = new DNSRecord( record );
					} );
			}
		} else {
			throw new Error( "DNSMessage must be created with raw buffer or object describing message content" );
		}
	}

	/**
	 * Decodes whole DNS message from sequence of octets.
	 *
	 * @param {Buffer} body sequence of octets describing DNS message in wire format
	 * @returns {void}
	 */
	parse( body ) {
		this.id = Decode.id( body );
		this.type = Decode.qr( body ) === 0 ? "request" : "response";

		this.responseCode = Decode.rcode( body );

		const opcodeNames = [ "query", "iquery", "status", null, "notify", "update" ];
		const opcode = Decode.opcode( body );
		this.opcode = opcodeNames[opcode] || null;

		this.authoritative = Boolean( Decode.aa( body ) );
		this.truncated = Boolean( Decode.tc( body ) );
		this.recursionDesired = Boolean( Decode.rd( body ) );
		this.recursionAvailable = Boolean( Decode.ra( body ) );
		this.authenticated = Boolean( Decode.ad( body ) );
		this.checkingDisabled = Boolean( Decode.cd( body ) );

		const sectionsCache = Decode.sections( body );

		for ( const section of SECTIONS ) {
			const count = Decode.recordCount( body, section );
			const records = this[section] = new Array( count );

			for ( let i = 0; i < count; i++ ) {
				records[i] = new DNSRecord( body, section, i, sectionsCache );
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

		for ( const section of SECTIONS ) {
			if ( this[section].length > 0 ) {
				info.push( Util.format( ";; %s SECTION:", section.toUpperCase() ) );

				for ( const record of this[section] ) {
					info.push( record.toString() );
				}
			}
		}

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
 * @property {?RawEDNSResourceRecord} edns EDNS-related information in case of record being OPT RR in compliance with RFC 6891
 */
class DNSRecord {
	/**
	 * @param {Buffer|object} body sequence of octets describing DNS record in wire format or data of DNS record extracted before
	 * @param {string} sectionName name of DNS message section this record is associated with
	 * @param {number} recordNum record's index into selected section's set of records
	 * @param {ParsedSectionsData} sectionsCache previously parsed information on records per section
	 */
	constructor( body, sectionName = undefined, recordNum = NaN, sectionsCache = null ) {
		this.name = null;
		this.type = null;
		this.class = null;

		if ( Buffer.isBuffer( body ) ) {
			if ( sectionName != null && recordNum > -1 ) {
				this.parse( body, sectionName, recordNum, sectionsCache || body );
			} else {
				throw new Error( "missing section name and record index for decoding record from wire format" );
			}
		} else if ( typeof body === "object" ) {
			Object.keys( body ).forEach( key => { this[key] = body[key]; } );
		} else
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
		const record = Decode.getRecord( sections, sectionName, recordNum );

		if ( sectionName === "additional" && this.edns ) {
			this.edns = record.edns;

			this.name = "";
			this.class = "IN";
			this.type = "OPT";

			return;
		}

		this.edns = null;

		this.name = record.name;
		this.class = classToLabel( record.class );
		this.type = typeToLabel( record.type );

		if ( !this.class )
			throw new Error( `Record #${recordNum} in section "${sectionName} has unknown class #${record.class}` );

		if ( !this.type )
			throw new Error( `Record #${recordNum} in section "${sectionName}" has unknown type #${record.type}` );

		if ( sectionName === "question" )
			return;

		this.ttl = record.ttl;

		const rdata = record.data;

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
				this.data = Decode.uncompress( body, rdata );
				break;

			case "IN TXT" :
				this.data = Decode.txt( body, rdata );
				if ( this.data.length === 0 )
					this.data = "";
				else if ( this.data.length === 1 )
					this.data = this.data[0];
				break;

			case "IN MX" :
				this.data = Decode.mx( body, rdata );
				break;

			case "IN SRV" :
				this.data = Decode.srv( body, rdata );
				break;

			case "IN SOA" :
				this.data = Decode.soa( body, rdata );
				this.data.rname = this.data.rname.replace( /\./, "@" );
				break;

			case "IN DS" :
				this.data = {
					keyTag: ( rdata[0] << 8 ) + rdata[1],
					algorithm: rdata[2],
					digestType: rdata[3],
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
		return this.class + " " + this.type;
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
