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
require 'uaa/user_account'
require 'stub_server'

describe CF::UAA::UserAccount do

  subject { CF::UAA::UserAccount.new(StubServer.url, 'Bearer example_access_token') }

  before :each do
    subject.trace = true
    StubServer.use_fiber = subject.async = true
    StubServer.responder do |request, reply|
      reply.headers[:content_type] = "application/json;charset=UTF-8"
      reply.body = %<{ "id":"random_id", "email":[#{@email_addrs}] }>
      reply
    end
  end

  it "should create a user account" do
    @email_addrs = '"jdoe@example.org"'
    StubServer.request do
      result = subject.create("jdoe", "password", "jdoe@example.org", "John", "Doe")
      result[:id].should == "random_id"
      result[:email].should =~ ["jdoe@example.org"]
      result[:password].should_not be
    end
  end

  it "should register a user with multiple email addresses" do
    @email_addrs = '"jdoe@gmail.com", "jdoe@example.org"'
    StubServer.request do
      result = subject.create("jdoe", "password", ["jdoe@example.org", "jdoe@gmail.com"], "John", "Doe")
      result[:id].should == "random_id"
      result[:email].should =~ ["jdoe@example.org", "jdoe@gmail.com"]
    end
  end

  it "should not be possible to register a user without an access token" do
    subject = CF::UAA::UserAccount.new(StubServer.url, nil)
    expect { subject.create("jdoe", "password", "jdoe@example.org", nil) }
        .to raise_exception(CF::UAA::AuthError)
  end

  it "should complain of bad response if a new user is not assigned an id" do
   StubServer.responder do |request, reply|
      reply.headers[:content_type] = "application/json;charset=UTF-8"
      reply.body = %<{ "non_id":"random_id", "email":["jdoe@example.org"] }>
      reply
    end
    StubServer.request do
      expect { subject.create("jdoe", "password", "jdoe@example.org") }
          .to raise_exception(CF::UAA::BadResponse)
    end
  end

  it "should change a user's password" do
    StubServer.responder do |request, reply|
      request.headers[:authorization].should == 'Bearer example_access_token'
      request.method.should == :put
      request.path.should == "/User/testUserId/password"
      request.headers[:content_type] =~ /application\/json/
      request.body.should == '{"password":"newPassw0rd"}'
      reply.status = 204
      reply
    end
    StubServer.request { subject.change_password("testUserId", "newPassw0rd") }
  end

  it "should raise an error for anything other than a 204 reply" do
    StubServer.responder { |request, reply| reply.status = 200; reply }
    StubServer.request do
      expect { subject.change_password("testUserId", "newPassw0rd") }
        .to raise_exception(CF::UAA::BadResponse)
    end
  end

  it "should find users by attribute value" do
    @keyattr = 'id'
    @attrname = 'foo'
    @attrvalue = 'bar'
    StubServer.responder do |request, reply|
      request.headers[:authorization].should == 'Bearer example_access_token'
      request.headers[:accept].should =~ /application\/json/
      request.method.should == :get
      request.path.should == "/Users?attributes=#{@keyattr}&filter=#{@attrname}+eq+%27#{@attrvalue}%27"
      reply.headers[:content_type] = "application/json;charset=UTF-8"
      reply.body = %<{"resources":[{"id":"aaf3af73-1a41-4918-89a3-bc9d73760a7e"}],"startIndex":1,"itemsPerPage":100,"totalResults":1,"schemas":["urn:scim:schemas:core:1.0"]}>
      reply
    end
    StubServer.request do
      output = subject.query_by_value(@keyattr, @attrname, @attrvalue)
      output[:totalResults].should == 1
      output[:resources][0][:id].should be
      puts output.inspect
    end
  end

  it "should delete a user" do
    @user_id = 'Test_User_Id'
    StubServer.responder do |request, reply|
      request.headers[:authorization].should == 'Bearer example_access_token'
      request.method.should == :delete
      request.path.should == "/User/#{@user_id}"
      reply
    end
    StubServer.request { subject.delete(@user_id) }
  end

  it "should complain if attempting to delete a user that does not exist" do
    @user_id = 'Test_User_Id2'
    StubServer.responder { |request, reply| reply.status = 404; reply }
    StubServer.request do
      expect { subject.delete(@user_id) }
        .to raise_exception(CF::UAA::NotFound)
    end
  end

  it "should complain if attempting to delete a user fails" do
    @user_id = 'Test_User_Id3'
    StubServer.responder { |request, reply| reply.status = 401; reply }
    StubServer.request do
      expect { subject.delete(@user_id) }
        .to raise_exception(CF::UAA::BadResponse)
    end
  end

  it "should not delete a user by name if not found" do
    @username = 'not-a-user'
    StubServer.responder do |request, reply|
      request.headers[:authorization].should == 'Bearer example_access_token'
      request.headers[:accept].should =~ /application\/json/
      request.method.should == :get
      request.path.should == "/Users?attributes=id%2Cactive&filter=username+eq+%27#{@username}%27"
      reply.headers[:content_type] = "application/json;charset=UTF-8"
      reply.body = %<{"resources":[],"startIndex":1,"itemsPerPage":100,"totalResults":0,"schemas":["urn:scim:schemas:core:1.0"]}>
      reply
    end
    StubServer.request do
      expect { subject.delete_by_name(@username) }
        .to raise_exception(CF::UAA::NotFound)
    end
  end

  it "should get user info from a user id" do
    @user_id = 'Test_User_Id4'
    StubServer.responder do |request, reply|
      request.headers[:authorization].should == 'Bearer example_access_token'
      request.headers[:accept].should =~ /application\/json/
      request.method.should == :get
      request.path.should == "/User/#{@user_id}"
      reply.headers[:content_type] = "application/json;charset=UTF-8"
      reply.body = %<{ "id":"#{@user_id}", "userName":"sam",
          "name":{"familyName":"sam","givenName":"sam"},
          "emails":[{"value":"joe@example.com"}], "userType":"User", "active":true,
          "meta":{"version":0,"created":"2012-03-30T19:57:38.290Z","lastModified":"2012-03-30T19:57:38.474Z"},
          "schemas":["urn:scim:schemas:core:1.0"] }>
      reply
    end
    StubServer.request do
      output = subject.get @user_id
      output[:id].should == @user_id
      output[:userName].should == "sam"
      output[:userType].should == "User"
      output[:name][:givenName].should == "sam"
      puts output.inspect
    end
  end

  it "should get user info from a user name" do
    @user_name = 'Test_User_5'
    @user_id = 'Test_User_Id_5'
    StubServer.responder do |request, reply|
      request.headers[:authorization].should == 'Bearer example_access_token'
      request.headers[:accept].should =~ /application\/json/
      request.method.should == :get
      reply.headers[:content_type] = "application/json;charset=UTF-8"
      if request.path == "/Users?attributes=id%2Cactive&filter=username+eq+%27#{@user_name}%27"
        reply.body = %<{"resources":[{"id":"#{@user_id}", "active":true}],"startIndex":1,"itemsPerPage":100,"totalResults":1,"schemas":["urn:scim:schemas:core:1.0"]}>
      elsif request.path == "/User/#{@user_id}"
        reply.body = %<{ "id":"#{@user_id}", "active":true, "userName":"#{@user_name}"}>
      else
        fail "bad request path"
      end
      reply
    end
    StubServer.request do
      output = subject.get_by_name @user_name
      output[:id].should == @user_id
      output[:userName].should == @user_name
      puts output.inspect
    end
  end

  it "should change password by user name" do
    @user_name = 'Test_User_6'
    @user_id = 'Test_User_Id_6'
    StubServer.responder do |request, reply|
      reply.headers[:content_type] = "application/json;charset=UTF-8"
      if request.path == "/Users?attributes=id%2Cactive&filter=username+eq+%27#{@user_name}%27"
        reply.body = %<{"resources":[{"id":"#{@user_id}", "active":true}],"startIndex":1,"itemsPerPage":100,"totalResults":1,"schemas":["urn:scim:schemas:core:1.0"]}>
      elsif request.path == "/User/#{@user_id}/password"
        request.headers[:authorization].should == 'Bearer example_access_token'
        request.headers[:accept].should =~ /application\/json/
        request.method.should == :put
        request.body.should == %<{"password":"new&password"}>
        reply.status = 204
      else
        fail "bad request path"
      end
      reply
    end
    StubServer.request do
      subject.change_password_by_name(@user_name, "new&password").should == true
    end
  end

end
