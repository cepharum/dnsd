// Copyright 2012 Iris Couch, all rights reserved.
//
// Server routines

"use strict";

const Net = require( "net" );
const Dgram = require( "dgram" );
const { EventEmitter } = require( "events" );

const { DNSMessage, DNSRecord } = require( "./message" );
const { seconds: asSeconds, serial: asSerial } = require( "./convenient" );
const { RCODES } = require( "./constants" );


const DefaultOptions = {
	ttl: 3600,
};


/**
 * Implements DNS server.
 */
class DNSServer extends EventEmitter {
	/**
	 * @param {function(Request, Response):void} requestHandler handles single incoming request
	 * @param {object} options customization options for server instance
	 */
	constructor( requestHandler, options = {} ) {
		super();

		this.log = console;
		this.zones = {};
		this.options = Object.assign( {}, DefaultOptions, options );

		if ( requestHandler )
			this.on( "request", requestHandler );

		this.udp = Dgram.createSocket( "udp4" );
		this.tcp = Net.createServer();

		this.udp.on( "close", () => { this.close(); } );
		this.tcp.on( "close", () => { this.close(); } );

		this.udp.on( "error", function( er ) { this.emit( "error", er ); } );
		this.tcp.on( "error", function( er ) { this.emit( "error", er ); } );

		this.tcp.on( "connection", connection => { this.onTcpConnection( connection ); } );
		this.udp.on( "message", ( msg, rInfo ) => { this.onUdp( msg, rInfo ); } );

		const listening = { tcp: false, udp: false };
		this.udp.once( "listening", function() {
			listening.udp = true;
			if ( listening.tcp )
				this.emit( "listening" );
		} );
		this.tcp.once( "listening", function() {
			listening.tcp = true;
			if ( listening.udp )
				this.emit( "listening" );
		} );
	}

	/**
	 * Adds another zone to server.
	 *
	 * @param {string} domainName domain name of zone (the common suffix of all names in this zone)
	 * @param {string} primaryNameServer domain name of zone's primary/master name server
	 * @param {string} adminAddress mail address of zone's administrator
	 * @param {number} serial serial number identifying current version of zone's definition
	 * @param {number} refresh number of seconds for a slave to wait before fetching zone from master server again
	 * @param {number} retry number of seconds for a slave to wait before trying to fetch zone again after failed attempt
	 * @param {number} expire number of seconds for a slave to wait before considering zone _gone_ while failing to fetch zone from master
	 * @param {number} ttl negative TTL, number of seconds for resolvers to wait before querying name servers of zone again after failed attempts
	 * @returns {DNSServer} current server for fluent interface
	 */
	zone( domainName, primaryNameServer, adminAddress, serial, refresh, retry, expire, ttl ) {
		const record = new DNSRecord( {
			class: "IN",
			type: "SOA",
			name: domainName,
			data: {
				mname: primaryNameServer,
				rname: adminAddress,
				serial: asSerial( serial ),
				refresh: asSeconds( refresh ),
				retry: asSeconds( retry ),
				expire: asSeconds( expire ),
				ttl: asSeconds( ttl || 0 ),
			}
		} );

		this.zones[record.name] = record;

		return this;
	}

	/**
	 * Requests server to start listening on selected port for incoming
	 * queries.
	 *
	 * @param {number} port number of IP port to listen on
	 * @param {string} ip IP to bind on listening
	 * @param {function():void} callback function invoked on successfully registering listener
	 * @returns {DNSServer} current server for fluent interface
	 */
	listen( port, ip, callback ) {
		let fn;

		this.port = port;

		if ( typeof ip === "function" ) {
			this.ip = "0.0.0.0";

			fn = ip;
		} else {
			this.ip = ip || "0.0.0.0";

			if ( typeof callback === "function" )
				fn = callback;
		}

		this.udp.bind( this.port, this.ip );
		this.tcp.listen( this.port, this.ip );

		Promise.all( [
			new Promise( ( resolve, reject ) => {
				this.udp.once( "listening", resolve );
				this.udp.once( "error", reject );
			} ),
			new Promise( ( resolve, reject ) => {
				this.tcp.once( "listening", resolve );
				this.tcp.once( "error", reject );
			} ),
		] )
			.then( () => {
				if ( fn ) {
					process.nextTick( fn );
				}

				process.nextTick( () => this.emit( "listening" ) );
			} )
			.catch( error => this.emit( "error", error ) );

		return this;
	}

	/**
	 * Shuts down running server.
	 *
	 * @returns {void}
	 */
	close() {
		if ( !this.$closing ) {
			this.$closing = true;

			this.udp.close();

			this.tcp.close( () => {
				this.emit( "close" );
			} );
		}
	}

	/**
	 * Handles new connection established on TCP port of server.
	 *
	 * @param {Socket} connection describes established TCP connection
	 * @returns {void}
	 * @protected
	 */
	onTcpConnection( connection ) {
		let expecting = -1;
		let received = 0;
		const chunks = [];

		/** @type {ServerSocket} */
		const socket = {
			type: "tcp",
			remoteAddress: connection.remoteAddress,
			remotePort: connection.remotePort,
			server: this,
			send: response => new Promise( ( resolve, reject ) => {
				if ( response == null ) {
					// don't waste a connection on a client asking for data this
					// server isn't authoritative for
					connection.end();
					resolve();
					return;
				}

				if ( !Buffer.isBuffer( response ) ) {
					throw new Error( "invalid response, must be Buffer" );
				}

				const length = response.length;

				if ( length > 65535 ) {
					throw new Error( "TCP responses greater than 65535 bytes not supported" );
				}

				connection.end( Buffer.concat( [ Buffer.from( [ length >> 8, length & 0xff ] ), response ] ), error => {
					if ( error ) {
						reject( error );
					} else {
						resolve();
					}
				} );
			} ),
		};

		connection.on( "data", chunk => {
			chunks.push( chunk );
			received += chunk.length;

			if ( expecting < 0 && received >= 2 ) {
				while ( chunks[0].length < 2 ) {
					chunks.splice( 0, 2, Buffer.concat( chunks.slice( 0, 2 ) ) );
				}

				expecting = chunks[0].readUInt16BE( 0 );
			}

			if ( expecting > -1 && received >= 2 + expecting ) {
				const buf = Buffer.concat( chunks ).slice( 2 );
				const message = buf.slice( 0, expecting );
				const request = new DNSRequest( message, socket );
				const response = new DNSResponse( message, socket );

				if ( this.isValidEDNS( request, response ) ) {
					this.emit( "request", request, response );
				}

				expecting = -1;
				received = buf.length - expecting;

				if ( received > 0 ) {
					chunks.splice( 0, chunks.length, buf.slice( expecting ) );
				} else {
					chunks.splice( 0 );
				}
			}
		} );
	}

	/**
	 * Handles new incoming UDP datagram with DNS query.
	 *
	 * @param {Buffer} query payload of received datagram containing DNS query
	 * @param {{address: string, family: string, port: number, size: number}} info describes context of datagram reception
	 * @returns {void}
	 * @protected
	 */
	onUdp( query, info ) {
		/** @type {ServerSocket} */
		const socket = {
			type: this.udp.type,
			remoteAddress: info.address,
			remotePort: info.port,
			server: this,
			send: response => new Promise( ( resolve, reject ) => {
				if ( response == null ) {
					resolve();
					return;
				}

				if ( !Buffer.isBuffer( response ) ) {
					throw new Error( "invalid response, must be Buffer" );
				}

				if ( response.length > 512 ) {
					throw new Error( "UDP responses greater than 512 bytes not yet implemented" );
				}

				this.udp.send( response, 0, response.length, info.port, info.address, error => {
					if ( error ) {
						reject( error );
					} else {
						resolve();
					}
				} );
			} ),
		};

		const request = new DNSRequest( query, socket );
		const response = new DNSResponse( query, socket );

		if ( this.isValidEDNS( request, response ) ) {
			this.emit( "request", request, response );
		}
	}

	/**
	 * Checks if request complies with EDNS requirements in RFC 6891.
	 *
	 * @param {DNSRequest} request incoming request to be handled
	 * @param {DNSResponse} response prepared response
	 * @returns {boolean} true if request may be handled by server callback, false if response has been transmitted already
	 */
	isValidEDNS( request, response ) {
		const records = request.findEDNSRecords();

		if ( records.length > 1 || ( records.length === 1 && records[0].section !== "additional" ) ) {
			this.respondOnInvalidEDNS( response, null, RCODES.FORMERR );
			return false;
		}

		if ( records.length === 1 ) {
			const { record: { edns } } = records[0];

			if ( edns.version > 0 ) {
				this.respondOnInvalidEDNS( response, edns, RCODES.BADVERS );
				return false;
			}
		}

		return true;
	}

	/**
	 * Responds to request with EDNS error.
	 *
	 * @param {DNSResponse} response response EDNS record is added to
	 * @param {?RawEDNSResourceRecord} requestorEDNS EDNS record optionally found request
	 * @returns {DNSRecord} EDNS record added to response
	 */
	addEDNSReply( response, requestorEDNS ) {
		const record = new DNSRecord( {
			edns: {
				udpSize: Math.max( requestorEDNS ? requestorEDNS.udpSize || 512 : 512, 512 ),
				extendedResult: 0,
				version: 0,
				flagDO: 0,
				flags: 0,
				options: [],
			},
			name: "",
			class: "IN",
			type: "OPT",
		} );

		response.additional.push( record );

		return record;
	}

	/**
	 * Responds to request with EDNS error.
	 *
	 * @param {DNSResponse} response response to use for replying
	 * @param {?RawEDNSResourceRecord} requestorEDNS EDNS record optionally found request
	 * @param {number} resultCode EDNS extended result code to use
	 * @returns {void}
	 */
	respondOnInvalidEDNS( response, requestorEDNS, resultCode ) {
		this.addEDNSReply( response, requestorEDNS );

		response.responseCode = resultCode;                                     // eslint-disable-line no-param-reassign

		response.end()
			.catch( error => {
				console.error( `responding on invalid EDNS request failed: ${error.message}` );
			} );
	}
}

/**
 * Implements common description of incoming DNS query in context of DNS
 * server.
 */
class DNSRequest extends DNSMessage {
	/**
	 * @param {Buffer} query describes DNS message received as query
	 * @param {ServerSocket} connection describes socket used to receive the request
	 */
	constructor( query, connection ) {
		super( query );

		this.connection = connection;
	}

	/**
	 * Prepares request for JSON serialization.
	 *
	 * @returns {object} description of current request as plain object
	 */
	toJSON() {
		const obj = {};

		Object.keys( this ).forEach( key => {
			if ( key !== "connection" )
				obj[key] = this[key];
		} );

		return obj;
	}
}

/**
 * Implements common manager of response to incoming DNS query in context of
 * DNS server.
 *
 * @property {RawEDNSResourceRecord} requestorEDNS EDNS data extracted from request message
 */
class DNSResponse extends DNSMessage {
	/**
	 * @param {Buffer} data describes querying DNS message to respond to
	 * @param {ServerSocket} connection describes socket used to receive the query
	 */
	constructor( data, connection ) {
		super( data );

		const ednsRecords = this.findEDNSRecords();
		this.requestorEDNS = ednsRecords.length === 1 && ednsRecords[0].section === "additional" ? ednsRecords.record.edns : null;

		this.question = this.question || [];
		this.answer = this.answer || [];
		this.authority = this.authority || [];
		this.additional = this.additional || [];

		this.connection = connection;

		this.type = "response";
	}

	/**
	 * Prepares response for JSON serialization.
	 *
	 * @returns {object} description of current response as plain object
	 */
	toJSON() {
		const obj = {};

		Object.keys( this ).forEach( key => {
			if ( key !== "connection" )
				obj[key] = this[key];
		} );

		return obj;
	}

	/**
	 * Compiles described response and sends it to querying peer.
	 *
	 * @param {*} value value to be included with response, deprecated in favor of more explicit use of API
	 * @returns {Promise<void>} promises response sent
	 */
	end( value = undefined ) {
		let that = this;


		if ( Array.isArray( value ) ) {
			this.answer = ( this.answer || [] ).concat( value );
			value = undefined;                                                  // eslint-disable-line no-param-reassign
		} else if ( value && typeof value == "object" ) {
			// eslint-disable-next-line consistent-this
			that = new DNSResponse( value, this.connection );
			value = undefined;                                                  // eslint-disable-line no-param-reassign
		}


		const questions = that.question = that.question || [];
		const answer = that.answer = that.answer || [];
		const authority = that.authority = that.authority || [];
		const additional = that.additional = that.additional || [];

		that.recursionAvailable = false;
		that.authoritative = true;


		for ( const question of questions ) {
			const soaRecord = this.findZoneForName( question.name );
			if ( !soaRecord ) {
				// don't respond to questions regarding zones we aren't authoritative for
				continue;
			}

			switch ( question.kind() ) {
				case "IN A" :
					if ( typeof value == "string" && answer.length === 0 ) {
						if ( questions.length > 1 ) {
							return Promise.reject( new Error( "can't handle simple answer to multiple questions" ) );
						}

						that.answer.push( {
							class: "IN",
							type: "A",
							name: question.name,
							data: value
						} );
					}
					break;

				case "IN SOA" :
					// convenience: implicitly provide authoritative SOA record to sole question
					if ( soaRecord && questions.length === 1 && answer.length === 0 && soaRecord.name === question.name ) {
						that.answer.push( soaRecord );
					}
					break;
			}

			// add SOA record if server is authoritative for sole question that didn't yield any answer
			if ( soaRecord && questions.length === 1 && answer.length === 0 && authority.length === 0 )
				that.authority.push( soaRecord );


			const minTTL = Math.max( ( soaRecord ? soaRecord.data.ttl : this.connection.server.options.ttl ) || 1, 1 );

			for ( const record of answer ) { wellFormedRecord( record, minTTL ); }
			for ( const record of authority ) { wellFormedRecord( record, minTTL ); }
			for ( const record of additional ) { wellFormedRecord( record, minTTL ); }
		}


		// ensure to have EDNS record in response if required
		const ednsRecords = this.findEDNSRecords();
		let ednsResponse;

		if ( this.requestorEDNS || this.responseCode > 0x0f ) {
			if ( ednsRecords.length > 1 || ( ednsRecords === 1 && ednsRecords[0].section !== "additional" ) ) {
				return Promise.reject( new Error( "invalid number or location of EDNS record(s) in response" ) );
			}

			if ( ednsRecords.length ) {
				ednsResponse = ednsRecords[0].record;
			} else {
				ednsResponse = this.connection.server.addEDNSReply( this, this.requestorEDNS );
			}
		}


		if ( this.responseCode > 0x0f ) {
			ednsResponse.edns.extendedResult = ( this.responseCode & 0xff0 ) >> 4;
		}


		return that.connection.send( that.answer.length > 0 || this.authority.length > 0 ? that.toBinary() : null );

		/**
		 * Fixes single DNS record.
		 *
		 * @param {DNSRecord} record record to be fixed
		 * @param {number} minTTL minimum TTL to use when missing TTL in record
		 * @returns {void}
		 */
		function wellFormedRecord( record, minTTL ) {
			if ( !record.class ) {
				record.class = "IN";                                            // eslint-disable-line no-param-reassign
			}

			if ( !record.ttl && !record.edns ) {
				record.ttl = minTTL;                                            // eslint-disable-line no-param-reassign
			}
		}
	}

	/**
	 * Looks for local definition of zone covering provided name.
	 *
	 * @param {string} name domain name
	 * @returns {?DNSRecord} found SOA record
	 */
	findZoneForName( name ) {
		let soaRecord;

		while ( name.length > 0 ) {
			soaRecord = this.connection.server.zones[name];
			if ( soaRecord )
				return soaRecord;

			const split = /^([^.\s]{1,63})(?:\.([^.\s].*))?$/.exec( name );
			if ( !split ) {
				throw new Error( "invalid name in query" );
			}

			name = split[2] == null ? "" : split[2];                            // eslint-disable-line no-param-reassign
		}

		return null;
	}
}


module.exports = function createServer( requestHandler, options = {} ) {    // eslint-disable-line no-param-reassign
	return new DNSServer( requestHandler, options );
};

module.exports.DNSServer = DNSServer;
module.exports.DNSRequest = DNSRequest;
module.exports.DNSResponse = DNSResponse;


/**
 * @typedef {object} SocketAddress
 * @property {string} address IP address
 * @property {string} family address family, such as "inet"
 * @property {number} port number of IP port
 */

/**
 * @typedef {object} ServerSocket
 * @property {string} type indicates type of socket
 * @property {string} remoteAddress provides IP address of querying peer
 * @property {number} remotePort provides port number of querying peer
 * @property {DNSServer} server exposes server instance this socket is part of
 * @property {function(Buffer):Promise} send sends provided DNS message to peer
 */
