// Copyright 2012 Iris Couch, all rights reserved.
//
// Encode DNS messages

"use strict";

const { SECTIONS, typeToNumber, classToNumber } = require( "./constants" );


/**
 * Encodes DNS message into sequence of octets representing that message in wire
 * format suitable for transmission.
 */
class Encoder {
	/** */
	constructor() {
		this.header = Buffer.alloc( 12 );
		this.position = 0;

		this.question = [];
		this.answer = [];
		this.authority = [];
		this.additional = [];

		// tracks positions of previously encoded domain names for name compression
		this.domains = {};
	}

	/**
	 * Retrieves sequence of octets describing message prepared in encoder.
	 *
	 * @returns {Buffer} description of message in wire format
	 */
	toBinary() {
		return Buffer.concat( [this.header].concat(
			this.question, this.answer, this.authority, this.additional
		) );
	}

	/**
	 * Encodes provided message in context of current encoder.
	 *
	 * @note This method isn't intended to be invoked multiple times per encoder
	 *       instance.
	 *
	 * @param {DNSMessage} msg message to be encoded
	 * @returns {Encoder} current instance
	 */
	message( msg ) {
		if ( !( msg instanceof require( "./message" ).DNSMessage ) ) {
			throw new TypeError( "message must be instance of DNSMessage" );
		}

		// ID
		this.header.writeUInt16BE( msg.id, 0 );

		// QR, opcode, AA, TC, RD
		let byte = 0;
		byte |= msg.type === "response" ? 0x80 : 0x00;
		byte |= msg.authoritative ? 0x04 : 0x00;
		byte |= msg.truncated ? 0x02 : 0x00;
		byte |= msg.recursionDesired ? 0x01 : 0x00;

		const opcodeNames = [ "query", "iquery", "status", null, "notify", "update" ];
		const opcode = opcodeNames.indexOf( msg.opcode );

		if ( opcode === -1 || typeof msg.opcode !== "string" )
			throw new Error( "Unknown opcode: " + msg.opcode );

		byte |= ( opcode & 0x0f ) << 3;

		this.header.writeUInt8( byte, 2 );

		// RA, Z, AD, CD, RCODE
		byte = 0;
		byte |= msg.recursionAvailable ? 0x80 : 0x00;
		byte |= msg.authenticated ? 0x20 : 0x00;
		byte |= msg.checkingDisabled ? 0x10 : 0x00;
		byte |= msg.responseCode & 0x0f;

		this.header.writeUInt8( byte, 3 );

		this.position = 12;

		for ( const section of SECTIONS ) {
			for ( const record of msg[section] || [] ) {
				if ( record.edns ) {
					this.ednsRecord( section, record );
				} else {
					this.record( section, record );
				}
			}
		}

		// Write the section counts.
		this.header.writeUInt16BE( this.question.length, 4 );
		this.header.writeUInt16BE( this.answer.length, 6 );
		this.header.writeUInt16BE( this.authority.length, 8 );
		this.header.writeUInt16BE( this.additional.length, 10 );

		return this;
	}

	/**
	 * Encodes provided EDNS OPT pseudo-RR record in selected section of
	 * currently encoded message.
	 *
	 * @param {string} sectionName name of section this record belongs to
	 * @param {DNSRecord} record EDNS records to be encoded
	 * @returns {void}
	 */
	ednsRecord( sectionName, record ) {
		const chunks = [];
		const { edns } = record;

		// encode empty name
		let buf = this.encodeName( "" );
		chunks.push( buf );
		this.position += buf.length;

		// compile flags
		let flags = 0;
		flags += ( edns.extendedResult & 0xff ) << 24;
		flags += ( edns.version & 0xff ) << 16;
		flags += edns.flagDO ? 0x8000 : 0;

		// encode custom header of OPT RR
		buf = Buffer.alloc( 8 );
		buf.writeUInt16BE( 41, 0 );
		buf.writeUInt16BE( edns.udpSize, 2 );
		buf.writeUInt16BE( flags, 4 );
		chunks.push( buf );
		this.position += 8;

		// encode variable-size options data
		const options = Array.isArray( edns.options ) ? edns.options : [];
		const optionsLength = Buffer.alloc( 2 );
		chunks.push( optionsLength );

		let length = 0;
		for ( const option of options ) {
			const { code, data } = option || {};

			if ( code > -1 && Buffer.isBuffer( data ) ) {
				length += 4 + data.length;

				buf = Buffer.alloc( 4 );
				buf.writeUInt16BE( code, 0 );
				buf.writeUInt16BE( data.length, 2 );
				chunks.push( buf );
				chunks.push( data );
			}
		}

		optionsLength.writeUInt16BE( length, 0 );


		this[sectionName].push( Buffer.concat( chunks ) );
	}

	/**
	 * Encodes provided resource record in selected section of currently encoded
	 * message.
	 *
	 * @param {string} sectionName name of section this record belongs to
	 * @param {DNSRecord} record instance of record to be encoded
	 * @returns {void}
	 */
	record( sectionName, record ) {
		const chunks = [];

		// Write the record name.
		let buf = this.encodeName( record.name );
		chunks.push( buf );
		this.position += buf.length;

		const type = typeToNumber( record.type );
		const classValue = classToNumber( record.class );

		// Write the type.
		buf = Buffer.alloc( 2 );
		buf.writeUInt16BE( type, 0 );
		chunks.push( buf );
		this.position += 2;

		// Write the class.
		buf = Buffer.alloc( 2 );
		buf.writeUInt16BE( classValue, 0 );
		chunks.push( buf );
		this.position += 2;

		if ( sectionName !== "question" ) {
			// Write the TTL.
			buf = Buffer.alloc( 4 );
			buf.writeUInt32BE( record.ttl || 0, 0 );
			chunks.push( buf );
			this.position += 4;

			// Write the rdata. Update the position now (the rdata length value) in case self.encode() runs.
			let match, rdata;

			switch ( record.class + " " + record.type ) {
				case "IN A" :
					rdata = record.data || "0.0.0.0";
					match = rdata.match( /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/ );
					if ( !match )
						throw new Error( "Bad " + record.type + " record data: " + JSON.stringify( record ) );

					rdata = [ Number( match[1] ), Number( match[2] ), Number( match[3] ), Number( match[4] ) ];
					break;

				case "IN AAAA" :
					rdata = ( record.data || "" ).split( /:/ );
					if ( rdata.length !== 8 )
						throw new Error( "Bad " + record.type + " record data: " + JSON.stringify( record ) );

					rdata = rdata.map( pair => {
						const qualified = ( "0000" + pair ).slice( -4 );

						if ( !qualified.match( /^[0-9a-f]{4}$/i ) )
							throw new Error( "invalid segment in IPv6 address" );

						return Buffer.from( qualified, "hex" );
					} );
					break;

				case "IN MX" :
					rdata = [
						buf16( record.data.weight ),
						this.encodeName( record.data.name, 2 + 2 ), // Adjust for the rdata length + preference values.
					];
					break;

				case "IN SOA" : {
					// fix notation of mail
					const parts = record.data.rname.split( "@" );
					let mail;

					if ( parts.length > 0 ) {
						parts[0] = parts[0].replace( /\./g, "\\." );
						mail = parts.join( "." );
					} else {
						mail = record.data.rname;
					}

					const mName = this.encodeName( record.data.mname, 2 );
					const rName = this.encodeName( mail, 2 + mName.length );

					rdata = [
						mName,
						rName,
						buf32( record.data.serial ),
						buf32( record.data.refresh ),
						buf32( record.data.retry ),
						buf32( record.data.expire ),
						buf32( record.data.ttl ),
					];
					break;
				}

				case "IN NS" :
				case "IN PTR" :
				case "IN CNAME" :
					rdata = this.encodeName( record.data, 2 ); // Adjust for the rdata length
					break;

				case "IN TXT" :
					rdata = ( Array.isArray( record.data ) ? record.data : [record.data] )
						.map( part => {
							const chunk = Buffer.from( String( part ) );
							return [ chunk.length, chunk ];
						} );
					break;

				case "IN SRV" :
					rdata = [
						buf16( record.data.priority ),
						buf16( record.data.weight ),
						buf16( record.data.port ),
						this.encodeName( record.data.target, 2 + 6, { compress: false } ), // Offset for rdata length + priority, weight, and port.
					];
					break;

				case "IN DS" :
					rdata = [
						buf16( record.data.keyTag ),
						Buffer.from( [record.data.algorithm] ),
						Buffer.from( [record.data.digestType] ),
						Buffer.from( record.data.digest ),
					];
					break;

				case "NONE A" :
					// I think this is no data, from RFC 2136 S. 2.4.3.
					rdata = [];
					break;

				default :
					throw new Error( "Unsupported record type: " + JSON.stringify( record ) );
			}

			// Write the rdata length. (The position was already updated.)
			rdata = toOctetList( rdata );
			buf = Buffer.alloc( 2 );
			buf.writeUInt16BE( rdata.length, 0 );
			chunks.push( buf );
			this.position += 2;

			// Write the rdata.
			this.position += rdata.length;
			if ( rdata.length > 0 )
				chunks.push( Buffer.from( rdata ) );
		}

		this[sectionName].push( Buffer.concat( chunks ) );
	}

	/**
	 * Encodes fully qualified domain name to become part of fully encoded
	 * message.
	 *
	 * @param {string} fqdn fully qualified domain name to encode
	 * @param {int} shift extra number of octets to be written before this name's encoding
	 * @param {boolean} compress controls whether name may be compressed (@see https://tools.ietf.org/html/rfc1035#section-4.1.4)
	 * @returns {Buffer} buffer containing encoded domain name
	 */
	encodeName( fqdn, shift = 0, { compress = true } = {} ) {
		let domain = fqdn.replace( /\.$/, "" );
		let position = this.position + shift;

		const chunks = [];

		while ( domain.length > 0 ) {
			const pointer = this.domains[domain];

			if ( pointer && compress && pointer <= 0x3fff ) {
				// suffix of current FQDN has been encoded before and can be re-used
				chunks.push( Buffer.from( [ 0xc0 + ( pointer >> 8 ), pointer & 0xff ] ) );
				return Buffer.concat( chunks );
			}

			// Encode the next part of the domain, saving its position in the lookup table for later.
			this.domains[domain] = position;

			const split = /^([^.\s]{1,63})(?:\.([^.\s].*))?$/.exec( domain );
			if ( !split ) {
				throw new TypeError( `domain name "${fqdn}" is malformed near "${domain}"` );
			}

			const segment = split[1];
			domain = split[2] == null ? "" : split[2];

			const chunk = Buffer.alloc( segment.length + 1 );
			chunk.write( segment, 1, segment.length, "ascii" );
			chunk.writeUInt8( segment.length, 0 );
			chunks.push( chunk );

			position += chunk.length;
		}

		// Encode the root domain and be done.
		chunks.push( Buffer.from( [0] ) );
		return Buffer.concat( chunks );
	}
}



/**
 * Converts provided integer value into 4-octet buffer containing that value in
 * big endian order.
 *
 * @param {int} value value to be written
 * @returns {Buffer} buffer containing provided value as 32-bit unsigned integer
 */
function buf32( value ) {
	const buf = Buffer.alloc( 4 );
	buf.writeUInt32BE( value, 0 );
	return buf;
}

/**
 * Converts provided integer value into 2-octet buffer containing that value in
 * big endian order.
 *
 * @param {int} value value to be written
 * @returns {Buffer} buffer containing provided value as 16-bit unsigned integer
 */
function buf16( value ) {
	const buf = Buffer.alloc( 2 );
	buf.writeUInt16BE( value, 0 );
	return buf;
}

/**
 * Converts provided data into flat sequence of octet values.
 *
 * @param {Buffer|Buffer[]|number|number[]} data probably deeply nested set of buffers and octet values
 * @returns {int[]} list of octets
 */
function toOctetList( data ) {
	if ( Buffer.isBuffer( data ) ) {
		return Array.prototype.slice.call( data );
	}

	if ( Array.isArray( data ) ) {
		return data.reduce( ( state, element ) => {
			if ( Buffer.isBuffer( element ) || Array.isArray( element ) ) {
				return state.concat( toOctetList( element ) );
			}

			state.push( element );
			return state;
		}, [] );
	}

	return [data];
}

exports.Encoder = Encoder;
