# frozen_string_literal: true

require_relative 'lib/upload_inspector/version'

Gem::Specification.new do |spec|
  spec.name = 'upload_inspector'
  spec.version = UploadInspector::VERSION
  spec.authors = ['Minh Doan']
  spec.email = ['minhdpc@gmail.com']

  spec.summary = 'Sanitize (CDR) and fail-closed checks for untrusted uploads: clean copies of images, video, SVG and CSV; ' \
                 'PDF, Office, zip and text verified.'
  spec.description = <<~DESC.tr("\n", " ").strip
    NEW in 0.9: UploadInspector.sanitize, content disarm and reconstruction (CDR). It writes a
    clean copy of an upload keeping only the parts known to be safe: EXIF with GPS location, XMP,
    comments, unknown chunks and payloads hidden in them (a PHP web shell in a JPEG comment, a
    zip in an MP4 box) are removed from PNG, JPEG, GIF, WebP, HEIC, AVIF, MP4 and QuickTime;
    SVG is rebuilt from an allowlist; CSV formulas can be neutralized; optional full re-encode
    through ruby-vips. The copy is checked again before it is written.
    Fail-closed checks for untrusted uploads: the real file type must be allowlisted and match
    the extension, and PDF, Office (OOXML, 97-2003, RTF, OpenDocument), zip, SVG, PNG, JPEG, GIF, WebP, HEIC, AVIF, MP4 and
    QuickTime files are verified structurally (scripts, macros, external links, appended data,
    zip and pixel bombs are rejected), as are CSV/TXT files (UTF-8 only, no binary, no HTML or
    script tags, no CSV injection). File names with hidden extensions (shell.php.jpg) or bidi
    tricks are rejected. Works with file paths, Rails uploads, Active Storage, any IO and S3
    objects uploaded through presigned URLs, and ships a Rails validator, a background job,
    type presets, a report-only shadow mode, ActiveSupport instrumentation and helpers to serve
    files safely (safe file names and response headers).
    Inspection runs in a resource-limited child process.
    Pure Ruby (libvips only for the optional re-encode), not an antivirus. If this gem helps you, a star on GitHub is much appreciated!
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
