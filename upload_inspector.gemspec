# frozen_string_literal: true

require_relative 'lib/upload_inspector/version'

Gem::Specification.new do |spec|
  spec.name = 'upload_inspector'
  spec.version = UploadInspector::VERSION
  spec.authors = ['Minh Doan']
  spec.email = ['minhdpc@gmail.com']

  spec.summary = 'Fail-closed structural inspection of untrusted uploads (PDF, Office, zip, images, HEIC/AVIF, MP4/MOV, S3).'
  spec.description = <<~DESC
    Checks uploaded files against an allowlist, verifies their detected type against the file
    extension, and applies format-specific structural checks. Rejects risky PDF content such as
    scripts and embedded files; Office macros, external relationships, and DDE fields; scripted
    SVGs; malformed or trailing data in PNG, JPEG, GIF, WebP, HEIC, AVIF, MP4 and QuickTime
    files, and oversized declared dimensions; and unsafe zip archives, including path traversal
    and decompression bombs. Inspection runs in a resource-limited child process. Pure Ruby; it
    is not an antivirus and does not detect malware signatures.
  
    Usage:
      UploadInspector.check(params[:file], allowed_types: %w[application/pdf image/heic video/mp4])
      UploadInspector.check(record.document, allowed_types: ...)   # Active Storage
      UploadInspector.check(io, filename: "a.pdf", allowed_types: ...)
      UploadInspector.check_s3(client: Aws::S3::Client.new, bucket: "b", key: "k.pdf", allowed_types: ...)
    Each returns a Result: safe?, reason, detail, detected_type.
  DESC
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 3.2'

  spec.metadata['rubygems_mfa_required'] = 'true'
  spec.metadata['changelog_uri'] = 'https://github.com/akarui2004/upload_inspector/blob/main/CHANGELOG.md'
  spec.metadata['documentation_uri'] = 'https://github.com/akarui2004/upload_inspector#usage'
  spec.metadata['source_code_uri'] = 'https://github.com/akarui2004/upload_inspector'
  spec.homepage = 'https://github.com/akarui2004/upload_inspector'

  spec.files = Dir['lib/**/*.rb', 'README.md', 'CHANGELOG.md', 'LICENSE.txt']
  spec.require_paths = ['lib']

  spec.add_dependency 'marcel', '~> 1.0'
  spec.add_dependency 'rubyzip', '>= 2.3', '< 4'
end
