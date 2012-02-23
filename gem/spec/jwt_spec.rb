require 'spec_helper'

require 'jwt'

describe "JWT decoding" do

  before :each do
    @test_token = JWT.encode({foo: "bar"}, "cloudcontrollersecret")
    @token = "eyJhbGciOiJIUzI1NiJ9.eyJpZCI6Ik5hTiIsInNjb3BlIjpbXSwiZW1haWwiOiJmb29AYmFyLmNvbSIsImV4cGlyZXNfaW4iOjQzMjAwLCJ1c2VyX2F1dGhvcml0aWVzIjpbIlJPTEVfVVNFUiJdLCJ1c2VyX2lkIjoiZm9vQGJhci5jb20iLCJjbGllbnRfaWQiOiJmb28ifQ.8nnqjZn0PKREaiMF_FkWOgzRFkPmXJCNC_BSJyhXyYg"
  end

  it "should be able to extract JSON from the token" do
    JWT.decode(@token, "cloudcontrollersecret").should_not be_nil
  end

  it "should succeed with nil secret if not verified" do
    JWT.decode(@token, nil, false).should_not be_nil
  end

  it "should fail with wrong secret" do
    expect { 
      JWT.decode(@token, "wrongsecret")
    }.should raise_exception(JWT::DecodeError)
  end

end
