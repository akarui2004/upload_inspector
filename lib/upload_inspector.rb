# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'marcel'
require 'tmpdir'
require 'zip'
require 'zlib'

require_relative 'upload_inspector/version'
require_relative 'upload_inspector/result'
require_relative 'upload_inspector/messages'
require_relative 'upload_inspector/policy'
require_relative 'upload_inspector/presets'
require_relative 'upload_inspector/filename'
require_relative 'upload_inspector/xml_scanner'
require_relative 'upload_inspector/pdf_object_parser'
require_relative 'upload_inspector/pdf_inspector'
require_relative 'upload_inspector/svg_inspector'
require_relative 'upload_inspector/image_inspector'
require_relative 'upload_inspector/iso_bmff_inspector'
require_relative 'upload_inspector/html_handler_scanner'
require_relative 'upload_inspector/text_inspector'
require_relative 'upload_inspector/ooxml_inspector'
require_relative 'upload_inspector/odf_inspector'
require_relative 'upload_inspector/cfb_reader'
require_relative 'upload_inspector/ole_inspector'
require_relative 'upload_inspector/rtf_inspector'
require_relative 'upload_inspector/zip_inspector'
require_relative 'upload_inspector/inspector'
require_relative 'upload_inspector/sanitizer'
require_relative 'upload_inspector/sandbox'
require_relative 'upload_inspector/source'
require_relative 'upload_inspector/s3'

# Fail-closed structural inspection of untrusted uploaded files.
# Only content proven to match a known-safe structure is accepted; anything
# unknown, unparsable, or erroring is rejected.
module UploadInspector
  # Rails helpers, loaded on first use so the gem does not depend on Rails.
  autoload :InspectJob, File.expand_path('upload_inspector/inspect_job', __dir__)

  MODES = %i[enforce report].freeze
  # Raster images and media render inline without running anything; everything else downloads.
  INLINE_TYPES = (Presets::IMAGES + Presets::MEDIA).freeze
  # Blocks scripts, plugins, forms and outside fetches if a served file is ever rendered as a page.
  CONTENT_SECURITY_POLICY = "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; sandbox"

  # Inspects an upload. Never raises on hostile input: always returns a Result.
  #
  #   UploadInspector.check('/tmp/x.pdf', filename: 'design.pdf', allowed_types: ['application/pdf'])
  #   UploadInspector.check(params[:file])           # Rails UploadedFile: name from original_filename
  #   UploadInspector.check(record.document)         # Active Storage attachment or blob
  #
  # +source+ is a path, File/Tempfile, Rails/Rack UploadedFile, Active Storage blob/attachment or
  # readable IO (see Source). +filename+ is the client-supplied name (its extension must agree
  # with the real content); taken from the source when it carries one, required otherwise.
  # +sandbox+ runs the inspection in a resource-limited child process (default true).
  # +mode+ :report runs every check but always accepts, setting Result#would_reject instead
  # (shadow mode, to measure rejections before enforcing). Other keywords are Policy options.
  #
  # With ActiveSupport loaded, each call publishes "check.upload_inspector" with payload
  # { mode:, reason:, would_reject:, detected_type:, filename_ext:, size: }.
  def self.check(source, filename: nil, sandbox: true, mode: :enforce, **policy_options)
    policy = Policy.new(**policy_options)
    observe(mode) { |payload| inspect_source(source, filename:, sandbox:, policy:, payload:) }
  end

  # Downloads and inspects an S3 object, e.g. one uploaded through a presigned URL.
  # +client+ is an Aws::S3::Client; +filename+ defaults to the key's basename.
  #
  #   result = UploadInspector.check_s3(client: s3, bucket: 'uploads', key: 'tmp/abc/report.pdf')
  #   s3.delete_object(bucket: 'uploads', key: 'tmp/abc/report.pdf') unless result.safe?
  def self.check_s3(client:, bucket:, key:, filename: nil, version_id: nil, sandbox: true, mode: :enforce, **policy_options)
    policy = Policy.new(**policy_options)
    observe(mode) { |payload| S3.check(client:, bucket:, key:, filename:, version_id:, sandbox:, policy:, payload:) }
  end

  # Checks an upload, then writes a cleaned copy to +to+ holding only the parts known to be safe
  # (content disarm and reconstruction): image metadata such as EXIF/GPS, comments and unknown
  # chunks are dropped, with any payload hidden in them. The copy is checked again before it is
  # moved to +to+; when the upload or the copy is rejected, nothing is written.
  #
  #   result = UploadInspector.sanitize(params[:file], to: '/tmp/clean.jpg', allowed_types: %w[image/jpeg])
  #   store(result.sanitized_path) if result.safe?
  #
  # +keep_orientation+ keeps the EXIF Orientation tag of a JPEG (and nothing else from EXIF),
  # so the image is not shown rotated. +neutralize_csv_formulas+ accepts CSV/TSV formula cells
  # and writes them with a leading ' so spreadsheets show them as text.
  # Other keywords are the same as for check, without +mode+.
  # Types that cannot be cleaned are rejected with :sanitize_unsupported.
  def self.sanitize(source, to:, filename: nil, sandbox: true, keep_orientation: false, neutralize_csv_formulas: false,
                    **policy_options)
    policy = Policy.new(**policy_options)
    Dir.mktmpdir('upload_inspector') do |workdir|
      output = File.join(workdir, 'sanitized')
      result = inspect_source(source, filename:, sandbox:, policy:, sanitize: { output:, keep_orientation:, neutralize_csv_formulas: })
      next result unless result.safe?

      FileUtils.mv(output, to)
      result.with(sanitized_path: File.path(to))
    end
  end

  # Name safe to store and serve for an upload; see Filename.sanitize.
  #
  #   UploadInspector.safe_filename('../x.php.jpg', detected_type: result.detected_type) # => "x_php.jpg"
  def self.safe_filename(name, detected_type:) = Filename.sanitize(name, detected_type:)

  # Response headers for serving a checked file back to users. Unsafe or unknown files are
  # served as a binary download. +inline+ is honoured for raster images and media only.
  #
  #   response.headers.merge!(UploadInspector.safe_headers(result, filename: upload.original_filename))
  def self.safe_headers(result, filename: nil, inline: false)
    type = result.safe? && result.detected_type
    type = 'application/octet-stream' unless type
    disposition = inline && INLINE_TYPES.include?(type) ? 'inline' : 'attachment'
    if filename
      name = Filename.sanitize(filename, detected_type: type)
      ascii = name.encode('US-ASCII', undef: :replace, invalid: :replace, replace: '_').delete('"\\')
      encoded = name.b.gsub(/[^A-Za-z0-9._-]/n) { |byte| format('%%%02X', byte.ord) }
      disposition += %(; filename="#{ascii}"; filename*=UTF-8''#{encoded})
    end
    type += '; charset=utf-8' if Presets::TEXT.include?(type)
    { 'Content-Type' => type, 'Content-Disposition' => disposition, 'X-Content-Type-Options' => 'nosniff',
      'Content-Security-Policy' => CONTENT_SECURITY_POLICY, }
  end

  # Inspection without mode handling or instrumentation (see check). Fills +payload+.
  # @api private
  # With +sanitize+ (Sanitizer options, output: included) the file is also rewritten.
  def self.inspect_source(source, filename:, sandbox:, policy:, payload: {}, sanitize: nil)
    # Active Storage knows the size up front: reject before downloading the blob to disk.
    size = source.respond_to?(:byte_size) ? source.byte_size.to_i : 0
    return Result.reject(:too_large, "#{size} bytes") if size > policy.max_file_size

    Source.open(source, filename:, max_size: policy.max_file_size) do |path, name|
      payload.merge!(filename_ext: File.extname(name.b.delete("\0")).downcase, size: File.size(path))
      # Checked here too (Inspector#verify! covers zip members): the sandbox payload is JSON,
      # which cannot carry a name that is not valid UTF-8.
      unsafe_name = Filename.unsafe_reason(name)
      next Result.reject(:filename_unsafe, unsafe_name) if unsafe_name
      next Sandbox.run(path, filename: name, policy:, sanitize:) if sandbox

      inspect_path(path, filename: name, policy:, sanitize:)
    end
  end

  # Inspects (and with +sanitize+, rewrites) a local file, in this process.
  # @api private
  def self.inspect_path(path, filename:, policy:, sanitize: nil)
    return Inspector.new(policy).call(path, filename:) unless sanitize

    Sanitizer.new(policy, **sanitize).call(path, filename:)
  end

  # Applies +mode+ to the Result of the block and publishes the check event.
  def self.observe(mode)
    mode = mode.to_sym
    raise ArgumentError, "mode must be one of: #{MODES.join(', ')}" unless MODES.include?(mode)

    payload = { mode: }
    instrument(payload) do
      result = yield payload
      result = result.reported if mode == :report
      payload.merge!(reason: result.reason, would_reject: result.would_reject, detected_type: result.detected_type)
      result
    end
  end
  private_class_method :observe

  def self.instrument(payload, &)
    return yield unless defined?(ActiveSupport::Notifications)

    ActiveSupport::Notifications.instrument('check.upload_inspector', payload, &)
  end
  private_class_method :instrument
end

autoload :UploadInspectorValidator, File.expand_path('upload_inspector/upload_inspector_validator', __dir__)
