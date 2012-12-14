# Gatling Test Scripts

## Overview

This is a self-contained module containing scripts written for the Gatling performance tool
(https://github.com/excilys/gatling/). The tests can be used to smoke-test a UAA instance or adjusted to
perform load or performance testing.

## Usage

The project is designed to run gatling using the Scala `sbt` build tool.

### Targeting a UAA

The UAA instance to target will be derived either from the environment variable `VCAP_BVT_TARGET` or from
the target setting in the Yeti `~/.bvt/config.yml` file. If neither of these are available, the scripts will be run
against the URL `http://localhost:8080/uaa`. The UAA admin client secret of your installation should be stored in
the environment variable `VCAP_BVT_ADMIN_SECRET`. Alternatively, you can modify the file `src/main/scala/uaa/Config`.

Running the script is slow as it runs the scala compiler each time. Using `sbt` is a much more efficient option.


### Running with `sbt`

Install `sbt` version 0.12 as described in [the bt website](http://www.scala-sbt.org/release/docs/Getting-Started/Setup).
The gatling directory is also an `sbt` project and includes a custom gatling plugin. You don't need to download the gatling
bundle in this case. The required jars will be downloaded by `sbt`.

Run sbt, and then type the `gatling` command from within the `sbt` console:

    $ sbt
    [info] Loading global plugins from /home/luke/.sbt/plugins
    [info] Loading project definition from /home/luke/uaa/gatling/project
    [info] Set current project to gatling (in build file:/home/luke/uaa/gatling/)
    > gatling

    Choose a simulation number:
         [0] AccountLockoutSimulation
         [1] ScimWorkoutSimulation
         [2] UaaBaseDataCreationSimulation
         [3] UaaSmokeSimulation
         [4] VarzSimulation

The environment variables for the UAA instance can be set as described in the previous section.

To test a UAA instance, first run the `UaaBaseDataCreationSimulation` to populate the system. This only needs to be done
once. Then try running the `UaaSmokeSimulation` which works out the system using the created data. This simulation
runs for a fixed duration (600 seconds, by default). This can be overridden by setting the `GATLING_DURATION`
environment variable to the desired number of seconds.

## Customization

The simulation classes have the suffix `Simulation` and reused code is refactored out into classes in the `uaa`
package, keeping the simulation files relatively short. The number of client users and
loop counters (or duration) can be modified in the simulation files to change the load as required. A simulation
consists of a sequence of "scenarios", each of which is configured something like this:

    vmcUserLogins.configure users 100 ramp 10 protocolConfig uaaHttpConfig

This means run the `vmcUserLogins` scenario with 100 test clients and ramp up to full capacity within 10 seconds.

If you are having problems, you can enable client-side logging by editing the logback configuration file
`src/main/resources/logback.xml`.






