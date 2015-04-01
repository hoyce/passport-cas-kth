/**
 * Cas
 */
var url = require('url'),
    http = require('http'),
    https = require('https'),
    passport = require('passport')

// query parameter used to request a gateway SSO
var gatewayParameter = 'useGateway=true';

/**
 * Creates an instance of `Strategy`.
 */
function Strategy(options, verify) {

  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) {
    throw new Error('cas authentication strategy requires a verify function');
  }

  this.ssoBase = options.ssoBaseURL;
  this.serverBaseURL = options.serverBaseURL;
  this.parsed = url.parse(this.ssoBase);
  if (this.parsed.protocol === 'http:') {
    this.client = http;
  } else {
    this.client = https;
  }

  passport.Strategy.call(this);

  this.name = 'cas';
  this._verify = verify;
}


/**
 * Authenticate request.
 *
 * @param req The request to authenticate.
 * @param options Strategy-specific options.
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var origUrl = req.originalUrl;

  var ticket = req.param('ticket');
  var service = url.resolve(this.serverBaseURL, origUrl);
  // check if gateway SSO requested, remove any
  // gateway query parameter from URL
  var serviceUrl = url.parse(service, true);
  delete serviceUrl.search;
  service = stripGatewayAuthenticationParameter(serviceUrl);

  if (!ticket) {
    // Building the redirect url to the login server
    var loginServerURL = url.parse(this.ssoBase + '/login', true);

    // Adding the gateway parameter if requested
    if (useGatewayAuthentication(req)) {
      loginServerURL.query.gateway = true;
    }

    // Adding the service parameter
    loginServerURL.query.service = service;

    // Redirecting to the login server.
    return this.redirect(url.format(loginServerURL));
  }

  // Formatting the service url and adding the nextUrl parameter after it's done due to double encoding
  // Adding the service parameter
  // Re-creates the original service URL.
  // Remove search and ticket since they are not valid now
  var baseServiceUrl = url.resolve(this.serverBaseURL, origUrl);
  var tmpUrl = url.parse(baseServiceUrl, true);
  delete tmpUrl.search;
  delete tmpUrl.query.ticket;
  var nextUrl = stripGatewayAuthenticationParameter(tmpUrl);
  var validateService = nextUrl;

  var self = this;

  /*
   * Verifies the user login add set error, fail or success depending on the result.
   */
  var verified = function (err, user, info) {
    if (err) { return self.error(err); }
    if (!user) { return self.fail(info); }
    self.success(user, info);
  };

  /**
   * Request the login server's /validate with the ticket and service parameters.
   * The callback function handles the CAS server response.
   * Read more at the "CAS protocol section 2.4.2": http://www.jasig.org/cas/protocol
   *
   * Response on ticket validation success:
   * yes
   * u1foobar
   *
   * Response on ticket validation failure:
   * no
   */
  var get = this.client.get({
    host: this.parsed.hostname,
    port: this.parsed.port,
    path: url.format({
      pathname: '/validate',
      query: {
        ticket: ticket,
        service: validateService
      }
    })
  }, function(response) {
    response.setEncoding('utf8');
    var body = '';

    response.on('data', function(responseData) {
      return body += responseData;
    });

    return response.on('end', function() {
      var responseLines = body.split('\n');
      if (responseLines.length >= 1) {
        if (responseLines[0] === 'no') {
          return self.fail(new Error('Authentication failed'));
        } else if (responseLines[0] === 'yes' && responseLines.length >= 2) {
          self._verify(responseLines[1], verified);
          return;
        }
      }
      return self.fail(new Error('The response from the server was bad'));
    });
  });

  get.on('error', function(e) {
    return self.fail(new Error(e));
  });
};

/**
 * Check if we are requested to perform a gateway signon, i.e. a check
 */
function useGatewayAuthentication(req) {
  // can be set on request if via application supplied callback
  if (req.useGateway == true) { return true; }

  // otherwise via query parameter
  var origUrl = req.originalUrl;
  var useGateway = false;
  var idx = origUrl.indexOf(gatewayParameter);
  if (idx >= 0) {
    useGateway = true;
  }

  return useGateway;
}

/**
 * If a gateway query parameter is added, remove it.
 */
function stripGatewayAuthenticationParameter(aUrl) {
  if (aUrl.query && aUrl.query.useGateway) {
    delete aUrl.query.useGateway;
  }
  if (aUrl.query.nextUrl) {
    var theNextUrl = decodeURIComponent(aUrl.query.nextUrl);
    aUrl.query.nextUrl = decodeURIComponent(theNextUrl);
  }
  var theUrl = url.format(aUrl);

  return theUrl;
}

/**
 * Expose `Strategy`.
 */
exports.Strategy = Strategy;