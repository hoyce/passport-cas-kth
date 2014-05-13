/**
 * Cas
 */
var url = require('url'),
    http = require('http'),
    https = require('https'),
    passport = require('passport')

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

    var ticket = req.param('ticket');
    var service = url.resolve(this.serverBaseURL, req.originalUrl);

    if (!ticket) {
        // Building the redirect url to the login server
        var loginServerURL = url.parse(this.ssoBase + '/login', true);

        // Adding the service parameter
        loginServerURL.query.service = service;

        // Redirecting to the login server.
        return this.redirect(url.format(loginServerURL));
    }

    // Coming back from login server with ticket included
    // Parses the service url to a object
    var serviceURL = url.parse(service, true);

    // Forces the url.format to use query instead of search by removing search
    delete serviceURL.search;

    // Remove the ticket parameter before validation
    delete serviceURL.query.ticket;

    // Extracts the nextUrl parameter because it's already encoded
    var nextUrl = serviceURL.query.nextUrl;

    // Delete the nextUrl parameter
    delete serviceURL.query.nextUrl;

    // Formatting the service url and adding the nextUrl parameter after it's done due to double encoding
    var validateService = url.format(serviceURL) + "?nextUrl=" + nextUrl;

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
 * Expose `Strategy`.
 */
exports.Strategy = Strategy;