/**
 * Module dependencies.
 */
var passport = require('passport')
  , util = require('util');


function Strategy( options, verify ){
	if( typeof options === "function" ){
		verify = options;
		options = {};
	}

	if( !verify ){
		throw new Error( "Token Authentication strategy requires a verify function" );
	}

	passport.Strategy.call( this );
	this.name = "token";
	this._verify = verify;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits( Strategy, passport.Strategy );

Strategy.prototype.authenticate = function( req ){
	var token = req.param( "token" );

	if( !( token||"" ).trim() ){
		return this.fail( 401 );
	}

	var self = this;

	this._verify( token, function( err, user ){
		if( err ){
			return self.error( err );
		}

		if( !user ){
			return self.fail( 401 );
		}

		self.success( user );
	});
};

module.exports = Strategy;
