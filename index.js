var argv = require('yargs')
    .usage('Sign, encrypt or decrypt UASIGN files')
    .option('tsp', {default: false})
    .option('tax', {default: true})
    .option('detached', {default: false})
    .option('role', {default: 'director'})
    .argv;

const agent = require('./agent');
agent.main(argv)
  .then((result)=> {
    // daemon was started and is still running
    if(typeof result === 'function') {
      return null;
    }
    process.exit(result ? 0 : 1)
  })
  .catch((error)=> {
    if(!(error instanceof agent.ReadFileError)) {
      console.error('Internal error');
    }
    if(argv.debug) {
      console.error('Details', error);
    }
    process.exit(1);
  });
