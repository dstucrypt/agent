var argv = require('yargs')
    .usage('Sign, encrypt or decrypt UASIGN files')
    .option('tsp', {default: false})
    .option('tax', {default: true})
    .option('detached', {default: false})
    .option('role', {default: 'director'})
    .argv;

const agent = require('./agent');
agent.run(argv);
