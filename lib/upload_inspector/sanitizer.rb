# frozen_string_literal: true

require_relative 'sanitizers/image_rewriter'

module UploadInspector
  # Content disarm and reconstruction: checks a file, writes a new one holding only the parts
  # known to be safe, then checks that output again (defense in depth). Nothing is written to
  # the caller's destination unless both checks pass (see UploadInspector.sanitize).
  class Sanitizer
    include Rejectable

    def initialize(policy, output:, keep_orientation: false)
      @policy = policy
      @output = output
      @keep_orientation = keep_orientation
    end

    # Boundary method: always returns a Result. The accepted Result is the check of the output.
    def call(path, filename:)
      checked = Inspector.new(@policy).call(path, filename:)
      return checked unless checked.safe?

      rewrite!(path, checked.detected_type)
      Inspector.new(@policy).call(@output, filename:)
    rescue Rejection => e
      Result.reject(e.reason, e.detail, detected_type: checked&.detected_type)
    rescue StandardError => e
      Result.reject(:inspection_failed, "#{e.class}: #{e.message}", detected_type: checked&.detected_type)
    end

  private

    def rewrite!(path, type)
      if ImageInspector::FORMATS.key?(type)
        Sanitizers::ImageRewriter.new(@policy, keep_orientation: @keep_orientation).rewrite(path, type, @output)
      else
        reject!(:sanitize_unsupported, type)
      end
    end
  end
end
