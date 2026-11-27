# frozen_string_literal: true

require 'test_helper'

# The integrations need gems from the Gemfile's optional :integration group
# (`bundle config set --local with integration`); their tests skip without them.
module IntegrationHelper
  def self.load(*features)
    features.each { |feature| require feature }
    true
  rescue LoadError
    false
  end
end
