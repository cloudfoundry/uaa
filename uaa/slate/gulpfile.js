const { watch, series, parallel } = require('gulp');
const { exec } = require('child_process');
const browserSync = require('browser-sync').create();

function displayErrors(err, stdout, stderr) {
  if (err != undefined) {
    console.log("\nERROR FOUND\n\n" + err);
    console.log("\nDUMPING STDOUT\n\n" + stdout);
    console.log("\nDUMPING STDERR\n\n" + stderr);
    process.exit();
  }
}

function middleman(cb) {
  exec('bundle exec middleman build', function(err, stdout, stderr) {
    if (err) return displayErrors(err, stdout, stderr);
    cb();
  });
}

function serve(cb) {
  browserSync.init({
    server: { baseDir: 'build' },
    port: 9000,
    files: 'build/**/*'
  });
  cb();
}

function watchFiles() {
  watch('source/**/*', middleman);
}

exports.default = series(middleman, parallel(serve, watchFiles));
