'use strict';

const PORT = process.env.OPENSHIFT_NODEJS_PORT || 9090
const HOSTNAME = process.env.OPENSHIFT_NODEJS_IP || '127.0.0.1'

const Hapi = require('hapi');
const server = new Hapi.Server();

function build(cb) {

    server.connection({
        host: HOSTNAME,
        port: PORT
    });

    server.register([
        require('./lib/hapi-ntlm'),
        require('./lib/auth')  
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
