exports.register = (server, options, next) => {

  const conf = require('./config.json');
  let generateToken = (request, reply, data) => {
    const token = "token";
    return { token }
  }

  server.auth.strategy('ntlm-auth-strategy', 'ntlm', false, {...conf, generateToken});

  server.route({
      method: 'GET',
      path: '/',
      config: {
          auth: 'ntlm-auth-strategy'
      },
      handler: (request, reply) => {
          reply({ ...request.auth.credentials }).code(201);
      }
  });

  next();
};

exports.register.attributes = {
  name: 'auth',
  version: '0.0.1'
}
