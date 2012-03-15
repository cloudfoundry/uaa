#
# Cloud Foundry 2012.02.03 Beta
# Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
#
# This product is licensed to you under the Apache License, Version 2.0 (the "License").
# You may not use this product except in compliance with the License.
#
# This product includes a number of subcomponents with
# separate copyright notices and license terms. Your use of these
# subcomponents is subject to the terms and conditions of the
# subcomponent's license, as noted in the LICENSE file.
#

# this must be required after the uaa/http (and hence em-http-request).

# webmock => 1.8.2 expects activate_connection to be present
# in em-http-client > 1. It is not present until 1.0.0.beta.4
# which we cannot use as we must work with eventmachine 0.12.10.
# Just stub in the call (which we don't need) here until
# version dependencies improve.
module EventMachine
	class HttpConnection
		def activate_connection
		end
	end
end	

require 'webmock/rspec'

