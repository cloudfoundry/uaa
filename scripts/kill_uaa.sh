#!/usr/bin/env bash

jps | grep Bootstrap | cut -f 1 -d' ' | xargs kill
