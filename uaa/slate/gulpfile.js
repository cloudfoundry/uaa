var gulp = require('gulp');
var exec = require('child_process').exec;
var webserver = require('gulp-webserver');

function displayErrors(err, stdout, stderr) {
  if(err != undefined) {
    console.log("\nERROR FOUND\n\n" + err);
    console.log("\nDUMPING STDOUT\n\n" + stdout);
    console.log("\nDUMPING STDERR\n\n" + stderr);
    process.exit();
  }
}

gulp.task('middleman', function(cb) {
  exec('bundle exec middleman build', function(err, stdout, stderr) {
    if(err) return displayErrors(err, stdout, stderr);
    cb();
  });
});

gulp.task('webserver', ['middleman'], function() {
  gulp.src('build').pipe(webserver({
    livereload: true,
    port: 9000
  }));
});

gulp.task('watch', function() {
  gulp.watch(['source/**/*'], ['middleman']);
});

gulp.task('default', ['middleman', 'webserver', 'watch']);