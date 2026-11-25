# frozen_string_literal: true

require_relative 'lib/upload_inspector/version'

Gem::Specification.new do |spec|
  spec.name = 'upload_inspector'
  spec.version = UploadInspector::VERSION
  spec.authors = ['Minh Doan']
  spec.email = ['minhdpc@gmail.com']

  spec.summary = 'Fail-closed structural inspection of untrusted uploads (PDF, Office, RTF, ODF, zip, images, video, CSV, Rails, S3).'
  spec.description = <<~DESC.tr("\n", " ").strip
    Fail-closed checks for untrusted uploads: the real file type must be allowlisted and match
    the extension, and PDF, Office (OOXML, 97-2003, RTF, OpenDocument), zip, SVG, PNG, JPEG, GIF, WebP, HEIC, AVIF, MP4 and
    QuickTime files are verified structurally (scripts, macros, external links, appended data,
    zip and pixel bombs are rejected), as are CSV/TXT files (UTF-8 only, no binary, no HTML or
    script tags, no CSV injection). File names with hidden extensions (shell.php.jpg) or bidi
    tricks are rejected. Works with file paths, Rails uploads, Active Storage, any IO and S3
    objects uploaded through presigned URLs, and ships a Rails validator, a background job,
    type presets, a report-only shadow mode, ActiveSupport instrumentation and helpers to serve
    files safely (safe file names and response headers). sanitize writes a cleaned copy (content
    disarm and reconstruction) of images, HEIC/AVIF/MP4, SVG and text: metadata such as GPS,
    comments and unknown chunks are dropped; optional re-encoding through ruby-vips.
    Inspection runs in a resource-limited child process.
    Pure Ruby, not an antivirus. If this gem helps you, a star on GitHub is much appreciated!
    Usage and options: https://akarui2004.github.io/upload_inspector
  DESC
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 3.2'

  spec.metadata['rubygems_mfa_required'] = 'true'
  spec.metadata['changelog_uri'] = 'https://github.com/akarui2004/upload_inspector/blob/main/CHANGELOG.md'
  spec.metadata['documentation_uri'] = 'https://akarui2004.github.io/upload_inspector'
  spec.metadata['source_code_uri'] = 'https://github.com/akarui2004/upload_inspector'
  spec.homepage = 'https://akarui2004.github.io/upload_inspector'

  spec.files = Dir['lib/**/*.rb', 'README.md', 'CHANGELOG.md', 'LICENSE.txt']
  spec.require_paths = ['lib']

  spec.add_dependency 'marcel', '~> 1.0'
  spec.add_dependency 'rubyzip', '>= 2.3', '< 4'
end
