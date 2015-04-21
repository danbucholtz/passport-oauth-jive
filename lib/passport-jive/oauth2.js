/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError;

var config = require('./config');

/**
 * `Strategy` constructor.
 *
 * The Jive authentication strategy authenticates requests by delegating to
 * Jive using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Jive application's client id
 *   - `clientSecret`  your Jive application's client secret
 *   - `callbackURL`   URL to which Jive will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new JiveStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/google/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'http://localhost:8080/oauth2/authorize';
  options.tokenURL = options.tokenURL || 'http://localhost:8080/oauth2/token';

  OAuth2Strategy.call(this, options, verify);
  this.name = 'jive-oauth';
  this._userProfileURL = options.userProfileURL || 'http://localhost:8080/api/core/v3/people/@me';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile from Google.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `jive`
 *   - `id`
 *   - `username`
 *   - `displayName`
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  this._oauth2.get(this._userProfileURL, accessToken, function (err, body, res) {
    if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

    try {
      // Jive returns fake json (grumble grumble), so make it valid.

      var object = bogusJsonCleanup(body);

      var profile = { provider: 'jive' };
      profile.id = object.id;
      profile.displayName = object.displayName;

      profile.username = object.jive.username;

      profile.emails = object.emails;

      profile._raw = body;
      profile._json = object;

      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
}

var bogusJsonCleanup = function(json){
  var indexOfObject = json.indexOf("{");
  var stringLength = json.length;
  var validJson = json.substring(indexOfObject, stringLength);
  var object = JSON.parse(validJson);
  return object;
};

/**
 * Return extra Google-specific parameters to be included in the authorization
 * request.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
Strategy.prototype.authorizationParams = function(options) {
  var params = {};
  if (options.accessType) {
    params['access_type'] = options.accessType;
  }
  if (options.approvalPrompt) {
    params['approval_prompt'] = options.approvalPrompt;
  }
  if (options.prompt) {
    // This parameter is undocumented in Google's official documentation.
    // However, it was detailed by Breno de Medeiros (who works at Google) in
    // this Stack Overflow answer:
    //  http://stackoverflow.com/questions/14384354/force-google-account-chooser/14393492#14393492
    params['prompt'] = options.prompt;
  }
  if (options.loginHint) {
    // This parameter is derived from OpenID Connect, and supported by Google's
    // OAuth 2.0 endpoint.
    //   https://github.com/jaredhanson/passport-google-oauth/pull/8
    //   https://bitbucket.org/openid/connect/commits/970a95b83add
    params['login_hint'] = options.loginHint;
  }
  if (options.userID) {
    // Undocumented, but supported by Google's OAuth 2.0 endpoint.  Appears to
    // be equivalent to `login_hint`.
    params['user_id'] = options.userID;
  }
  if (options.hostedDomain || options.hd) {
    // This parameter is derived from Google's OAuth 1.0 endpoint, and (although
    // undocumented) is supported by Google's OAuth 2.0 endpoint was well.
    //   https://developers.google.com/accounts/docs/OAuth_ref
    params['hd'] = options.hostedDomain || options.hd;
  }
  return params;
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
