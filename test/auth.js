exports.register = (server, options, next) => {

  const conf = require('./config.json');

  const generateInfo = async (request, reply, result) => {
    return await Promise.resolve('info');
  }

  server.auth.strategy('ntlm-auth-strategy', 'ntlm', false, { ...conf,
    generateInfo
  });

  server.route({
    method: 'GET',
    path: '/',
    config: {
      auth: 'ntlm-auth-strategy'
    },
    handler: (request, reply) => {
      reply({ ...request.auth.credentials
      }).code(201);
    }
  });

  next();
};

exports.register.attributes = {
  name: 'auth',
  version: '0.0.1'
}
