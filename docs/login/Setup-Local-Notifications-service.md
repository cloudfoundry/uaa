##Introduction
This document outlines how to setup a local notifications service.

# Prerequisites

    - a) mysql
    - b) SMTP server
    - c) UAA server

# Step 1

Clone notifications repository

    - a) Clone the notifications repository at 'https://github.com/cloudfoundry-incubator/notifications.git' into '~/workspace/go/src/github.com/cloudfoundry-incubator/'

# Step 2

Download and setup GO

    - a) Download go version go1.2.1 and extract it to a directory of your choice.
    - b) Edit the ~/.bash_profile and add the following lines to it:
            export GOPATH="$HOME/workspace/go"
            export GOROOT="$HOME/go" (This is if you've extracted go in the home directory. If not, set the path to your go1.2.1 as the GOROOT)
            export PATH="$GOROOT/bin:$GOPATH/bin:$PATH"
# Step 3

Create a database

    - a) Connect to mysql
    - b) Create a database called 'notifications_development'

# Step 4

Setup the development environment for the notifications services

    - a) Create a file called development under '~/workspace/go/src/github.com/cloudfoundry-incubator/notifications/bin/env'
    - b) Add the following environment variables to the file:

         | Variable                | Description                         | Default  |
         | -------------------     | ----------------------------------- | -------- |
         | CC_HOST\*               | Cloud Controller Host               | \<none\> |
         | DATABASE_URL\*          | URL to your Database                | \<none\> |
         | PORT                    | Port that application will bind to  | 3000     |
         | ROOT_PATH\*             | Root path of your application       | \<none\> |
         | SMTP_HOST\*             | SMTP Host                           | \<none\> |
         | SMTP_PASS\*             | SMTP Password                       | \<none\> |
         | SMTP_PORT\*             | SMTP Port                           | \<none\> |
         | SMTP_TLS                | Use TLS when talking to SMTP server | true     |
         | SMTP_USER\*             | SMTP Username                       | \<none\> |
         | SENDER\*                | Emails are sent from this address   | \<none\> |
         | UAA_CLIENT_ID\*         | The UAA client ID                   | \<none\> |
         | UAA_CLIENT_SECRET\*     | The UAA client secret               | \<none\> |
         | UAA_HOST\*              | The UAA Host                        | \<none\> |
         | VERIFY_SSL              | Verifies SSL                        | true     |
         | TEST_MODE               | Run in test mode                    | false    |
         | GOBBLE_MIGRATIONS_DIR\* | $ROOT_PATH/gobble/migrations        | \<none\> |
         * required

# Step 5

Start the notifications service

    - a) cd ~/workspace/go/src/github.com/cloudfoundry-incubator/notifications
    - b) go get github.com/tools/godep
    - c) godep restore
    - d) bin/run

            [WEB] Booting with configuration:
            [WEB]   CCHost           -> https://api.10.244.0.34.xip.io
            [WEB]   DatabaseURL      -> root:@tcp(127.0.0.1:3306)/notifications_development?parseTime=true
            [WEB]   DBLoggingEnabled -> false
            [WEB]   InstanceIndex    -> 0
            [WEB]   Port             -> 3001




