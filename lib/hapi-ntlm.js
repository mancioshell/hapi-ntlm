'use strict';

const Boom = require('boom');
const ntlm_client = require('ntlm-ad-client')

const internals = {};

const handleAuthenticationHeader = (request, reply) => {
    const response = reply();
    response.header('WWW-Authenticate', 'NTLM');
    response.statusCode = 401;
}

exports.register = (server, options, next) => {
    server.auth.scheme('ntlm', internals.implementation);
    next();
};

internals.implementation = (server, options) => {

    let client

    return {
        authenticate: (request, reply) => {

            let user = request.connection.ntlm;

            if (user) return reply.continue({
                credentials: user
            });

            if (!request.connection.client) {
                client = ntlm_client(options)
                request.connection.client = client
            } else {
                client = request.connection.client;
            }

            let auth_headers = request.headers.authorization;

            if (!auth_headers) return handleAuthenticationHeader(request, reply);

            let ntlm_message = auth_headers.split(' ')[1];
            if (ntlm_message.length !== 2) return reply(Boom.unauthorized('Not a valid NTLM Token'));

            if (!request.connection.ntlm_auth) {
                client.negotiate(ntlm_message, (err, challenge) => {
                    if (err) return reply(Boom.unauthorized(err));
                    request.connection.ntlm_auth = true;
                    const response = reply()
                    response.statusCode = 401;
                    response.header('WWW-Authenticate', challenge.toString('base64'));
                    return;
                })
            }

            if (request.connection.ntlm_auth) {
                client.authenticate(ntlm_message, (err, result) => {
                    if (err) return reply(Boom.unauthorized(err));
                    request.connection.ntlm = result;
                    return reply.continue({
                        credentials: result
                    });
                })
            }
        }
    }
}

exports.register.attributes = {
    pkg: require('../package.json')
};
