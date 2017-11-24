const PORT = 3000
const HOSTNAME = '0.0.0.0'

const Hapi = require('hapi');
const server = new Hapi.Server();

function build(cb) {
    server.connection({
        host: HOSTNAME,
        port: PORT
    });

    server.register([
        require('../index'),
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
