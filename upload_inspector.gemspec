# frozen_string_literal: true

require_relative 'lib/upload_inspector/version'

Gem::Specification.new do |spec|
  spec.name = 'upload_inspector'
  spec.version = UploadInspector::VERSION
  spec.authors = ['Minh Doan']
  spec.email = ['minhdpc@gmail.com']

  spec.summary = 'Fail-closed structural inspection of untrusted uploads (PDF, Office, zip).'
  spec.description = <<~DESC
    Rejects uploaded files whose real type does not match the allowlist or the file extension,
    PDFs with active content (JavaScript, launch actions, embedded files, also inside compressed
    object streams), Office documents with macros, OLE objects, external relationships, DDE fields,
    and dangerous zip archives. Runs in a resource-limited child process. Pure Ruby, no AV engine.
  DESC
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 3.2'

  spec.metadata['rubygems_mfa_required'] = 'true'
  spec.metadata['changelog_uri'] = 'https://github.com/akarui2004/upload_inspector/blob/main/CHANGELOG.md'
  spec.metadata['source_code_uri'] = 'https://github.com/akarui2004/upload_inspector'
  spec.homepage = 'https://github.com/akarui2004/upload_inspector'

  spec.files = Dir['lib/**/*.rb', 'README.md', 'CHANGELOG.md', 'LICENSE.txt']
  spec.require_paths = ['lib']

  spec.add_dependency 'marcel', '~> 1.0'
  spec.add_dependency 'rubyzip', '>= 2.3', '< 4'
end
