# frozen_string_literal: true

require_relative 'lib/upload_inspector/version'

Gem::Specification.new do |spec|
  spec.name = 'upload_inspector'
  spec.version = UploadInspector::VERSION
  spec.authors = ['Minh Doan']
  spec.email = ['minhdpc@gmail.com']

  spec.summary = 'Sanitize (CDR), malware scanning, CLI, and fail-closed checks for untrusted uploads: clean copies of ' \
                 'images, video, SVG, CSV; PDF, Office, zip verified; Active Storage, Shrine, CarrierWave, Rack.'
  spec.description = <<~DESC.tr("\n", " ").strip
    Fail-closed structural inspection and content disarm and reconstruction (CDR) for untrusted uploads.
    UploadInspector.sanitize writes a clean copy keeping only parts known to be safe (strips EXIF/GPS,
    XMP, comments, unknown chunks/boxes from PNG, JPEG, GIF, WebP, HEIC, AVIF, MP4, QuickTime; rebuilds
    SVG from an allowlist; neutralizes CSV formulas; optional ruby-vips re-encode).
    Structural checks reject macros, PDF JavaScript/actions, OLE objects, remote templates, DDE, zip bombs,
    image polyglots, and dangerous filenames (hidden extensions, bidi tricks).
    Malware scanning (0.10): pluggable scanner adapters including ClamAV (clamd INSTREAM via pure-Ruby socket),
    custom command binaries, and AWS GuardDuty Malware Protection for S3 tags.
    Integrations & CLI (0.11): upload_inspector CLI (check, scan directory, sanitize), signed Active Storage
    analyzer, Shrine plugin, CarrierWave mixin, and Rack middleware. Works with Rails uploads, S3 presigned URLs,
    and plain IO in a resource-limited child process.
    Pure Ruby (libvips only for optional re-encode).
    Usage and options: https://akarui2004.github.io/upload_inspector
  DESC
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 3.2'

  spec.metadata['rubygems_mfa_required'] = 'true'
  spec.metadata['changelog_uri'] = 'https://github.com/akarui2004/upload_inspector/blob/main/CHANGELOG.md'
  spec.metadata['documentation_uri'] = 'https://akarui2004.github.io/upload_inspector'
  spec.metadata['source_code_uri'] = 'https://github.com/akarui2004/upload_inspector'
  spec.homepage = 'https://akarui2004.github.io/upload_inspector'

  spec.files = Dir['lib/**/*.rb', 'exe/*', 'README.md', 'CHANGELOG.md', 'LICENSE.txt']
  spec.bindir = 'exe'
  spec.executables = ['upload_inspector']
  spec.require_paths = ['lib']

  spec.add_dependency 'marcel', '~> 1.0'
  spec.add_dependency 'rubyzip', '>= 2.3', '< 4'
end
