# frozen_string_literal: true

source 'https://rubygems.org'

gemspec

gem 'minitest', '~> 5.20'
gem 'rake', '~> 13.0'

# CI pins rubyzip to cover both supported major versions.
gem 'rubyzip', ENV['RUBYZIP_VERSION'] if ENV['RUBYZIP_VERSION']
