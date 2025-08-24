# Testing considerations

This document contains information about how the tests are structured and why.

## Types of test

There are two types of tests:

- Unit tests, which run tests on classes or subsets of the application in a single JVM. Those run with `./gradlew test`.
- Integration tests, which launch the UAA application and run web-based tests the running app. Those can be run with
  `./gradlew integrationTest`

## Helper scripts

There are helper scripts, `run-unit-tests.sh` and `run-integration-tests.sh`, which run the tests inside a docker
container. The docker container they run in contains the database against which to run the tests, as well as an LDAP
server. It is self-contained but lacks flexibility. It relies on custom-baked image that may not support arm64 and
can't work with your IDE.

However, since the scripts run a container with all dependencies, you do not need infrastructure to run against a
specified DB:

    $ run-unit-tests.sh <dbtype>

## Test databases

By default, the tests run against an in-memory DB, `hsqldb`. This DB is also present in the prod artifact, so that
UAA can also be run standalone to test tweaks in a live instance.

To run these databases locally, use the docker-compose script:

    $ docker compose --file scripts/docker-compose.yml up

If you wish to launch only one of the DBs, select the appropriate service name:

    $ docker compose --file scripts/docker-compose.yml up postgresql

To run tests against either Postgres or MySQL, use the `postgresql` or `mysql` profile, to select the DB. Be sure
to add the `default` profile which will trigger seeding the database with some admin users, clients, etc. For example:

    $ ./gradlew '-Dspring.profiles.active=mysql test

To run tests from your IDE against a given database, you can (temporarily) annotate the test class:

```java

@ActiveProfiles({"mysql"})
class MyCustomTests {
    @Test
    void foo() {
        // ...
    }
}
```

## Database-specific tests

Some tests only work on a single type of database, for example `MySqlDbMigrationIntegrationTest`; or do not work on a
given database, for example `JdbcClientMetadataProvisioningTest.createdByPadsTo36Chars`. You can turn tests on and off
based on the profile with custom annotations, `@DisabledIfProfile` and `@EnabledIfProfile`, for example:

```java
// Only run on either mysql or postgresql
@EnabledIfProfile({"mysql", "postgresql"})
class RealDbOnlyTests {

}

// or:

class SomeTests {

    // Do not run when there is either mysql or postgresql
    @DisabledIfProfile({"mysql", "postgres"})
    void notOnRealDb() {

    }

}
```

## Test pollution

There might be test-pollution when tests are run in parallel or even between projects. For example, when you run

    $ ./gradlew test

It will run tests in both `cloudfoundry-identity-server` and `cloudfoundry-identity-uaa` projects. Both need a database,
and both do sometimes clean up the database.

To avoid test pollution, 24 databases are created, and each Gradle "worker" thread gets its own database. A Gradle
worker has a numeric `id`, and each time a new task is spun up, the idea of the worker picking up the task increases.
So there are 24 DBs with names `uaa_1`, `uaa_2`, ... created, and usually the worker ID stays below 24 and there are
enough databases for each test.

However, if the Gradle daemon is kept running in the background and is re-used for later tasks, e.g., by doing:

    $ ./gradlew test # first run
    # do some code changes
    $ ./gradlew test

You will get new workers with IDs > 24. It is recommended you run your Gradle in no-daemon mode when running tests:

    $ ./gradlew test --no-daemon

It will be slightly slower to start up (a few seconds), but the tests take multiple minutes, and so the gain of using
a daemon is not worth the trouble.

## Timezone issues

The UAA and its DB server _MUST_ have the same timezone, because dates are not uniformly stored in UTC and timezones
do matter. Specifically, for MySQL, there are issues when your local host is ahead of UTC, because:

1. The default containers run in UTC
2. When calling `current_timestamp` the value is in UTC
3. But when calling a prepared statement from JDBC, with a Date/Timestamp/time-based, the timezone is sent to the server

So, when running e.g. in `Europe/Paris` (CET):

```java
jdbcTemplate.queryForObject("SELECT CURRENT_TIMESTAMP",String .class);
// will return 15:00UTC
// if the TZ is dropped, it is recorded as 15:00
jdbcTemplate.update("UPDATE foo SET updated=?",new Date(System.currentTimeMillis()));
// will insert 16:00CET
// if the TZ is dropped, this is recorded as 16:00
```

For this reason, we update the MySQL container in `docker-compose.yml` to have the same timezone as the host through
the `$TZ` env var.

If you have timing-based issues in your test, ensure that you set `$TZ` before starting docker compose, e.g.:

    $ TZ="Europe/Paris" docker compose up

It is not required, and MySQL will default to using UTC.

## Running tests in parallel

Depending on the machine used for tests, HSQL-based tests are twice as fast as Postgres or MySQL tests. The bottleneck
project is `cloudfoundry-identity-uaa`. Tests for other projects are much faster, and since each project is tested in
parallel, they all complete before the longer `cloudfoundry-identity-uaa` test is over.

While it makes sense to run tests in parallel for `cloudfoundry-identity-uaa` when testing locally, it has a few
consequences. First, it might bring it test pollution, see [above](#test-pollution). Second, the databases must be able
to handle the incoming connections, but this is handled by setting the number of concurrent connections to 250 on both
Postgres and MySQL.

Furthermore, too many tests running in parallel have diminishing returns because the Spring testing support caches
ApplicationContext between tests to avoid bootstrapping too many contexts. Having many tests in parallel means there
will be a lot of cache misses, and every Gradle worker handling a test will have to bootstrap multiple
ApplicationContext, which is usually quite slow. A value that has been previously used is six workers in parallel, and,
for any given project, four tests in parallel. Since `cloudfoundry-identity-uaa` is the bottleneck, we make its tests run
in parallel, and keep other projects running sequential tests. Empirically, this yields a x2 or more speedup on the test
suite on a powerful developer machine. Increasing parallelism further yields no benefits (for example, tests are
slightly slower on a Mac M1 using six tests in parallel).

Technically, parallelism is controlled by two parameters:

- `org.gradle.workers.max` in `gradle.properties`, set to 6. This means that there are no more than six Gradle processes
  running at any given time. It does not have anything to do with tests directly. This might mean you have three compile
  processes for three different projects, as well as three test processes for different projects. Within a given project, by
  default, tests are running sequentially and never in parallel. Unless you configure parallelism for tests, see below:
- `maxParallelForks` in the test task in the project's `build.gradle`, set to 4. This controls how many tests can run in
  parallel within a given project. It is bounded by the max workers set above — so if there are five compile tasks running,
  and one test task, the test task will run tests sequentially as there is a single worker available left.

With this setup, we get 11 test workers total, 4 for `cloudfoundry-identity-uaa`, plus 1 per remaining project:

- `cloudfoundry-identity-metrics-data`
- `cloudfoundry-identity-statsd-lib`
- `cloudfoundry-identity-model`
- `cloudfoundry-identity-statsd`
- `cloudfoundry-identity-server`

Since `cloudfoundry-identity-uaa` depends on all the projects, it runs last, and gets workers 8, 9, 10 and 11. If some
tests did not need to be re-run because the code hasn't changed in some projects, it may get assigned workers with lower
IDs. This means that we need all databases between `uaa_1` and `uaa_11`, included. To make sure we have enough room for
future changes, we will keep the current setup with 24 databases, see [test pollution](#test-pollution).

In single-CPU scenarios (i.e., in CI), we would only need two databases, `uaa_7` for`cloudfoundry-identity-server` and
`uaa_8` for `cloudfoundry-identity-uaa`.