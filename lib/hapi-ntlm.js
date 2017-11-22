'use strict';

const Boom = require('boom');
const Hoek = require('hoek');
const Joi = require('joi');
const ntlm_client = require('ntlm-ad-client')

const internals = {};

internals.defaults = {
    path: null,
    use_tls: false,
    tls_options: null,
    generateToken: null
};

internals.schema = Joi.object().keys({
    hostname: Joi.string().required(),
    port: Joi.string().required(),
    domain: Joi.string(),
    path: Joi.string().allow(null),
    use_tls: Joi.boolean(),
    tls_options: Joi.boolean().allow(null),
    generateToken: Joi.func().allow(null)
});


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

    Hoek.assert(options, 'Missing NTLM auth strategy options');

    const settings = Hoek.applyToDefaults(internals.defaults, options);
    Joi.assert(settings, internals.schema);

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
                    const { token } = settings.generateToken ? settings.generateToken(request, reply, result) : ''
                    const credentials = {...result, token}
                    request.connection.ntlm = credentials;

                    return reply.continue({
                      credentials: credentials
                    });

                })
            }
        }
    }
}

exports.register.attributes = {
    pkg: require('../package.json')
};
