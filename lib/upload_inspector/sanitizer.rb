# frozen_string_literal: true

require_relative 'sanitizers/image_rewriter'
require_relative 'sanitizers/iso_bmff_rewriter'
require_relative 'sanitizers/svg_rewriter'
require_relative 'sanitizers/text_rewriter'

module UploadInspector
  # Content disarm and reconstruction: checks a file, writes a new one holding only the parts
  # known to be safe, then checks that output again (defense in depth). Nothing is written to
  # the caller's destination unless both checks pass (see UploadInspector.sanitize).
  class Sanitizer
    include Rejectable

    def initialize(policy, output:, keep_orientation: false, neutralize_csv_formulas: false)
      @policy = policy
      @output = output
      @keep_orientation = keep_orientation
      @neutralize_csv_formulas = neutralize_csv_formulas
    end

    # Boundary method: always returns a Result. The accepted Result is the check of the output.
    def call(path, filename:)
      # Formulas are let through the first check only to be neutralized; the output check refuses them.
      input_policy = @neutralize_csv_formulas ? @policy.with(allow_csv_formulas: true) : @policy
      checked = Inspector.new(input_policy).call(path, filename:)
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
      elsif IsoBmffInspector::TYPES.include?(type)
        Sanitizers::IsoBmffRewriter.new(@policy).rewrite(path, type, @output)
      elsif type == SvgInspector::TYPE
        Sanitizers::SvgRewriter.new.rewrite(path, @output)
      elsif TextInspector::TYPES.include?(type)
        Sanitizers::TextRewriter.new(neutralize_csv_formulas: @neutralize_csv_formulas).rewrite(path, type, @output)
      else
        reject!(:sanitize_unsupported, type)
      end
    end
  end
end
