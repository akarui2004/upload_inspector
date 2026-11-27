# frozen_string_literal: true

require 'carrierwave'
require 'fileutils'
require 'tmpdir'

module UploadInspector
  # CarrierWave uploader mixin: rejects unsafe files when they are cached, like CarrierWave's
  # own allowlists (the model gets an integrity error with the rejection message).
  #
  #   class DocumentUploader < CarrierWave::Uploader::Base
  #     include UploadInspector::CarrierWave
  #     def upload_inspector_options = { allowed_types: UploadInspector::Presets::DOCUMENTS }
  #
  #     process :upload_inspector_sanitize # optional: store a cleaned copy (see UploadInspector.sanitize)
  #   end
  module CarrierWave
    # First of the cache callbacks: processing (also a before-cache callback) must not see
    # an unchecked file.
    def self.included(base)
      callbacks = base._before_callbacks
      base._before_callbacks = callbacks.merge(cache: [:upload_inspector_check!, *callbacks[:cache]])
    end

    # UploadInspector.check keywords; override in the uploader.
    def upload_inspector_options = {}

    # Result of the last check, nil before one ran.
    attr_reader :upload_inspector_result

    # Replaces the cached file with a cleaned copy. Types that cannot be cleaned (PDF, Office)
    # passed the check on cache and are kept as they are.
    def upload_inspector_sanitize
      Dir.mktmpdir('upload_inspector') do |dir|
        output = File.join(dir, 'sanitized')
        result = UploadInspector.sanitize(current_path, to: output, filename: original_filename.to_s,
                                                        **upload_inspector_options.except(:mode))
        next if result.reason == :sanitize_unsupported
        raise ::CarrierWave::ProcessingError, result.message unless result.safe?

        FileUtils.mv(output, current_path)
      end
    end

    private

    def upload_inspector_check!(new_file)
      source = new_file.path || new_file # files without a path (StringIO) are read
      @upload_inspector_result = UploadInspector.check(source, filename: new_file.original_filename.to_s,
                                                               **upload_inspector_options)
      raise ::CarrierWave::IntegrityError, @upload_inspector_result.message unless @upload_inspector_result.safe?
    end
  end
end
