
module Cloudfoundry::Uaa

  # Error to indicate that the caller should prompt for credentials and
  # try again.
  class PromptRequiredError < RuntimeError
    attr_reader :prompts
    def initialize(prompts)
      @prompts = prompts
    end
  end

  class AuthError < RuntimeError; end

end
