#--
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
#++

require 'spec_helper'
require 'stringio'
require 'cli'

module CF::UAA

describe TCli do

  def do_stdio(stdin_str = '')
    o_stdin, o_stdout, o_stderr = $stdin, $stdout, $stderr
    $stdin, $stdout, $stderr = StringIO.new(stdin_str), StringIO.new, StringIO.new
    yield
    [$stdout.string, $stderr.string]
  ensure
    $stdin, $stdout, $stderr = o_stdin, o_stdout, o_stderr
  end

  ["-v", "version", "--version", "v"].each do |opt|
    it "should display a version with #{opt}" do
      stdout, stderr = do_stdio { TCli.run("", [opt]) }
      stdout.should match VERSION
    end
  end



end

end
