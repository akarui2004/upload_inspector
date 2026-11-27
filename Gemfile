# frozen_string_literal: true

source 'https://rubygems.org'

gemspec

gem 'minitest', '~> 5.20'
gem 'rake', '~> 13.0'

# CI pins rubyzip to cover both supported major versions.
gem 'rubyzip', ENV['RUBYZIP_VERSION'] if ENV['RUBYZIP_VERSION']

# Tests for the optional Rails helpers (validator, job); not a runtime dependency.
gem 'activejob', '>= 7.1'
gem 'activemodel', '>= 7.1'

# Optional: sanitize(reencode: true). Enable with `bundle config set --local with vips` (needs libvips).
group :vips, optional: true do
  gem 'ruby-vips', '~> 2.2'
end

# Tests for the optional integrations (Shrine, CarrierWave, Active Storage analyzer, Rack).
# Enable with `bundle config set --local with integration`; never a runtime dependency.
group :integration, optional: true do
  gem 'activestorage', '>= 7.1'
  gem 'carrierwave', '>= 3.0'
  gem 'rack', '>= 2.2'
  gem 'shrine', '~> 3.5'
end
