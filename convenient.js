// Copyright 2012 Iris Couch, all rights reserved.
//
// Convenience routines to make it easier to build a service

"use strict";

module.exports = {
	/**
	 * Generates serial for use in SOA records.
	 *
	 * @param {*} value provided serial
	 * @returns {number|*} serial describing "now", otherwise provided value
	 */
	serial( value ) {
		if ( !value || value === "now" ) {
			const now = new Date;

			return Math.floor( now.getTime() / 1000 );
		}

		return value;
	},

	/**
	 * Converts certain strings into number of seconds.
	 *
	 * @param {*} value value to check for string describing amount of time
	 * @returns {number|*} number of seconds found in value, provided value if conversion fails
	 */
	seconds( value ) {
		const match = /^\s*(\d+)\s*([smhdw])\s*$/i.exec( value );
		if ( match ) {
			const [ , amount, unit ] = match;

			switch ( unit.toLowerCase() ) {
				case "s" : return Number( amount );
				case "m" : return Number( amount ) * 60;
				case "h" : return Number( amount ) * 60 * 60;
				case "d" : return Number( amount ) * 60 * 60 * 24;
				case "w" : return Number( amount ) * 60 * 60 * 24 * 7;
			}
		}

		return value;
	},
};
