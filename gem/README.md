CloudFoundry UAA Gem
====================

Client gem for interacting with the CloudFoundry UAA server.

Set up a local ruby environment (so sudo not required):

    $ rvm use 1.9.2

Build the gem

    $ bundle install
    $ rake build

Install it

    $ rake install

Run it

    $ uaa
      Usage: uaa [options] command [<args>] [command_options]
         or: uaa help command
    $ uaa login vcap_tester@vmware.com tester
    LSAJDHF873e8feDKJHLK
    $ uaa --client_id app --client_secret appclientsecret decode LSAJDHF873e8feDKJHLK
    {"user_id":"vcap_tester@vmware.com","client_id":"app","scope":["read"]...}

Use the gem:

    #!/usr/bin/env ruby
    require 'uaa/client'
    client = CF::UAA::Client.new
    token_info = client.decode_token "LSAJDHF873e8feDKJHLK"

## Tests

Run the tests with rake:

    $ rake

Use an env var to get coverage reports:

    $ COVERAGE=true rake

Use an env var to run integration tests (using a server at
`uaa.vcap.me`):

    $ INTEGRATION_TEST=true rake
