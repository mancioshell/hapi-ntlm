'use strict';

const Boom = require('boom');
const Hoek = require('hoek');
const Joi = require('joi');
const ntlm_client = require('ntlm-ad-client')

const internals = {};
const cache = {};

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


const handleAuthenticationHeader = (request, reply, cookie) => {
  const response = reply();
  response.header('WWW-Authenticate', 'NTLM');
  response.statusCode = 401;
}

const uuidv4 = () => {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    var r = Math.random() * 16 | 0,
      v = c == 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

exports.register = (server, options, next) => {
  server.auth.scheme('ntlm', internals.implementation);
  next();
};

internals.implementation = (server, options) => {

  Hoek.assert(options, 'Missing NTLM auth strategy options');

  const settings = Hoek.applyToDefaults(internals.defaults, options);
  Joi.assert(settings, internals.schema);

  server.state('session', {
    ttl: 1000 * 60 * 60 * 24,
    encoding: 'base64json',
    isSecure: false,
    path : '/'
  })

  let client

  return {
    authenticate: (request, reply) => {

      let cookie = request.state.session;

      if (!cookie) {
        cookie = {
          id: uuidv4()
        }
        const response = reply();
        return response.state('session', cookie).redirect(request.path)
      }

      if (!cache[cookie.id]) {
        cache[cookie.id] = {}
      }

      let user = cache[cookie.id].ntlm;

      if (user) return reply.continue({
        credentials: user
      });

      if (!cache[cookie.id].client) {
        client = ntlm_client(options)
        cache[cookie.id].client = client;
      } else {
        client = cache[cookie.id].client;
      }

      let auth_headers = request.headers.authorization;

      if (!auth_headers) return handleAuthenticationHeader(request, reply, cookie);
      let ntlm_message = auth_headers.split(' ')[1];

      if (!cache[cookie.id].ntlm_auth) {
        client.negotiate(ntlm_message, (err, challenge) => {
          if (err) {
            delete cache[cookie.id]
            return reply(Boom.unauthorized(err));
          }
          cache[cookie.id].ntlm_auth = true;
          const response = reply()
          response.statusCode = 401;
          response.header('WWW-Authenticate', challenge.toString('base64'));
          return;
        })
      }

      if (cache[cookie.id].ntlm_auth) {
        client.authenticate(ntlm_message, (err, result) => {
          if (err) {
            delete cache[cookie.id]
            return reply(Boom.unauthorized(err));
          }
          const {
            token
          } = settings.generateToken ? settings.generateToken(request, reply, result) : ''
          const credentials = { ...result,
            token
          }
          cache[cookie.id].ntlm = credentials;
          delete cache[cookie.id].client;
          delete cache[cookie.id].ntlm_auth;

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
