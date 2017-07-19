[![NPM version](https://img.shields.io/npm/v/hapi-ntlm.svg?style=flat)](https://www.npmjs.com/package/hapi-ntlm)

# hapi-ntlm

An hapi authentication strategy to hanlde NTLM-authentication.

This module use [ntlm-ad-client](https://github.com/einfallstoll/ntlm-ad-client) under the hood and is heavily inspired by [express-ntlm](https://github.com/einfallstoll/express-ntlm) written by [Fabio Poloni](https://github.com/einfallstoll)

## install

    $ npm install hapi-ntlm

## example usage - auth.js

    exports.register = (server, options, next) => {

      let domain = 'YOUR_DOMAIN';
      let hostname = 'YOUR_AD_HOSTNAME';
      let port = 'YOUR_AD_POST';
      let path = null;
      let use_tls = false;
      let tls_options = undefined;

      let authOptions = {
          domain,
          hostname,
          port,
          path,
          use_tls,
          tls_options
      }

      server.auth.strategy('ntlm-auth-strategy', 'ntlm', false, authOptions);

      server.route({
          method: 'GET',
          path: '/',
          config: {
              auth: 'ntlm-auth-strategy'
          },
          handler: (request, reply) => {
              reply({
                  'msg': request.auth.credentials
              }).code(201);
          }
      });

      next();
    };

    exports.register.attributes = {
      name: 'auth',
      version: '0.0.1'
    }

## example usage - server.js

    const PORT = 3000
    const HOSTNAME = '127.0.0.1'

    const Hapi = require('hapi');
    const server = new Hapi.Server();

    function build(cb) {
        server.connection({
            host: HOSTNAME,
            port: PORT
        });

        server.register([
            require('hapi-ntlm'),
            require('./auth')  
        ], (err) => {
            cb(err, server);
        });
    }

    build((err, server) => {
        if (err) {
            console.error(err);
            throw err;
        }
        server.start((err) => {
            if (err) {
                throw err;
            }
            console.info('Server running at:', server.info.uri);
        });
    });

## options

  | Name | type | description |
  |------|------|-------------|
  | `hostname` | `string` | Hostname of the Active Directory. |
  | `port` | `string` | Port of the Active Directory. |
  | `domain` | `string` | Default domain if the DomainName-field cannot be parsed. |
  | `path` | `string` | Base DN. *not implemented yet* |
  | `use_tls` | `boolean` | Indicates wether to use TLS or not. |
  | `tls_options` | `object` | An options object that will be passed to [tls.connect](https://nodejs.org/api/tls.html#tls_tls_connect_options_callback) and [tls.createSecureContext](https://nodejs.org/api/tls.html#tls_tls_createsecurecontext_options). __Only required when using ldaps and the server's certificate is signed by a certificate authority not in Node's default list of CAs.__ (or use [NODE_EXTRA_CA_CERTS](https://nodejs.org/api/cli.html#cli_node_extra_ca_certs_file) environment variable)|
  | `tls_options.ca` | `string` /  `array` / `Buffer` | Override the trusted CA certificates provided by Node. Refer to [tls.createSecureContext](https://nodejs.org/api/tls.html#tls_tls_createsecurecontext_options) |
