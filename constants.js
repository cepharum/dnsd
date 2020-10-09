// Copyright 2012 Iris Couch, all rights reserved.
//
// Looking up and converting between various constants

"use strict";

module.exports = {
	type: swapType,
	class: swapClass,
	typeToLabel,
	typeToNumber,
	classToLabel,
	classToNumber,
};

const TYPE_LABELS = {
	1: "A",
	2: "NS",
	3: "MD",
	4: "MF",
	5: "CNAME",
	6: "SOA",
	7: "MB",
	8: "MG",
	9: "MR",
	10: "NULL",
	11: "WKS",
	12: "PTR",
	13: "HINFO",
	14: "MINFO",
	15: "MX",
	16: "TXT",
	17: "RP",
	18: "AFSDB",
	19: "X25",
	20: "ISDN",
	21: "RT",
	22: "NSAP",
	23: "NSAP-PTR",
	24: "SIG",
	25: "KEY",
	26: "PX",
	27: "GPOS",
	28: "AAAA",
	29: "LOC",
	30: "NXT",
	31: "EID",
	32: "NIMLOC",
	33: "SRV",
	34: "ATMA",
	35: "NAPTR",
	36: "KX",
	37: "CERT",
	38: "A6",
	39: "DNAME",
	40: "SINK",
	41: "OPT",
	42: "APL",
	43: "DS",
	44: "SSHFP",
	45: "IPSECKEY",
	46: "RRSIG",
	47: "NSEC",
	48: "DNSKEY",
	49: "DHCID",
	50: "NSEC3",
	51: "NSEC3PARAM",
	52: "TLSA",
	// 53 - 54 unassigned
	55: "HIP",
	56: "NINFO",
	57: "RKEY",
	58: "TALINK",
	59: "CDS",
	// 60 - 98 unassigned
	99: "SPF",
	100: "UINFO",
	101: "UID",
	102: "GID",
	103: "UNSPEC",
	104: "NID",
	105: "L32",
	106: "L64",
	107: "LP",
	// 108 - 248 unassigned
	249: "TKEY",
	250: "TSIG",
	251: "IXFR",
	252: "AXFR",
	253: "MAILB",
	254: "MAILA",
	255: "*",
	256: "URI",
	257: "CAA",
	// 258 - 32767 unassigned
	32768: "TA",
	32769: "DLV",
	// 32770 - 65279 unassigned
	// 65280 - 65534 Private use
	65535: "Reserved",
};

const CLASS_LABELS = {
	0: "reserved",
	1: "IN",
	2: null,
	3: "CH",
	4: "HS",
	// 5 - 127 unassigned classes
	// 128 - 253 unassigned qclasses
	254: "NONE",
	255: "*",
	// 256 - 32767 unassigned
	// 32768 - 57343 unassigned
	// 57344 - 65279 unassigned qclasses and metaclasses
	// 65280 - 65534 Private use
	65535: "reserved",
};

const TYPE_NUMBERS = transpose( TYPE_LABELS );
const CLASS_NUMBERS = transpose( CLASS_LABELS );

/**
 * Maps numeric value representing type of RR into its label or vice versa.
 *
 * @param {string|number} input value or label representing/describing type of RR
 * @returns {number|string} counterpart to provided value
 */
function swapType( input ) {
	return typeof input === "string" ? typeToNumber( input ) : typeToLabel( input );
}

/**
 * Maps numeric value representing class of RR into its label or vice versa.
 *
 * @param {string|number} input value or label representing/describing class of RR
 * @returns {number|string} counterpart to provided value
 */
function swapClass( input ) {
	return typeof input === "string" ? classToNumber( input ) : classToLabel( input );
}

/**
 * Maps provided value representing RR type in wire format into label describing
 * it.
 *
 * @param {int} value value representing RR type in wire format
 * @returns {?string} label describing RR type
 */
function typeToLabel( value ) {
	if ( isNaN( value ) || typeof value !== "number" || value < 1 || value > 65535 )
		throw new Error( `Invalid record type: ${value}` );

	return TYPE_LABELS[value] || ( value > 65279 ? "Private use" : null );
}

/**
 * Maps provided label of RR type into its value for use in binary encoded wire
 * format.
 *
 * @param {string} label label of RR type
 * @returns {number} integer representing that class in wire format
 */
function typeToNumber( label ) {
	if ( typeof label != "string" )
		throw new Error( `Type must be string: ${label}` );

	const num = TYPE_NUMBERS[label];
	if ( num )
		return num;

	throw new Error( `No such type label: ${label}` );
}

/**
 * Maps provided value representing RR class in wire format into label
 * describing it.
 *
 * @param {int} value value representing RR class in wire format
 * @returns {?string} label describing RR class
 */
function classToLabel( value ) {
	if ( isNaN( value ) || typeof value != "number" || value < 1 || value > 65535 )
		throw new Error( `Invalid record class: ${value}` );

	return CLASS_LABELS[value] || ( value > 65279 ? "Private use" : null );
}

/**
 * Maps provided label of RR class into its value for use in binary encoded wire
 * format.
 *
 * @param {string} label label of RR class
 * @returns {number} integer representing that class in wire format
 */
function classToNumber( label ) {
	if ( typeof label !== "string" )
		throw new Error( `Type must be string: ${label}` );

	const num = CLASS_NUMBERS[label];
	if ( num )
		return num;

	throw new Error( `No such class label: ${label}` );
}


/**
 * Retrieves reverse mapping of provided one.
 *
 * @param {object<number,string>} mapping mapping of binary values into per-value labels
 * @returns {object<string,number>} reversal mapping
 */
function transpose( mapping ) {
	const result = {};

	Object.keys( mapping ).forEach( key => {
		const val = mapping[key];
		if ( typeof val === "string" )
			result[val] = Number( key );
	} );

	return result;
}
