# Gatling Test Scripts

## Overview

This is a self-contained module containing scripts written for the Gatling performance tool
(https://github.com/excilys/gatling/). The tests can be used to smoke-test a UAA instance or adjusted to
perform load or performance testing.

## Usage

Download and unpack the `gatling-charts-highcharts` bundle, version 1.1. Set the `GATLING_HOME` environment
variable to point to this directory.

Change to the `uaa/gatling` directory and run the `gatling` script there. It should give you a menu of the available
simulations:

    $ ./gatling
    GATLING_HOME already set to: /Users/luke/Work/tools/gatling-charts-highcharts-1.1.0-SNAPSHOT
    -----------
    Gatling cli
    -----------

    Which simulation do you want to execute ?

     - uaa
         [0] createUsers
         [1] loadLogin

    Simulation #:

By default, the scripts will be run against the URL `http://localhost:8080/uaa`. To use a different UAA, set the
environment variable `GATLING_UAA_BASE` to point to the instance you want to test.


## Customization

The simulation scripts are in the directory called `simulations` and reused code is refactored out into files in
the directory `simulations/uaa`, keeping the simulation files relatively short. The number of client users and
loop counters (or duration) can be modified in the simulation files to change the load as required.

TODO: List existing simulations and what they do.





