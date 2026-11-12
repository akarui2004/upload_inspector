# frozen_string_literal: true

module UploadInspector
  MEGABYTE = 1024 * 1024

  # Inspection limits and allowlists. Defaults are deliberately strict (PDF only).
  #
  # allowed_types      - MIME types whose structure this gem can verify (PDF family, OOXML, zip).
  # allow_unverifiable - MIME types accepted on real-type + extension match only, because their
  #                      content cannot be inspected (e.g. image/vnd.adobe.photoshop). Opt-in risk.
  Policy = Data.define(
    :allowed_types, :allow_unverifiable, :max_file_size,
    :max_zip_entries, :max_zip_entry_size, :max_zip_total_size, :max_compression_ratio,
    :max_inflate_size, :timeout, :memory_limit, :cpu_limit
  )

  class Policy
    DEFAULTS = {
      allowed_types: ['application/pdf'],
      allow_unverifiable: [],
      max_file_size: 500 * MEGABYTE,
      max_zip_entries: 5_000,
      max_zip_entry_size: 200 * MEGABYTE,
      max_zip_total_size: 1024 * MEGABYTE,
      max_compression_ratio: 100,
      max_inflate_size: 50 * MEGABYTE, # per PDF object stream / per OOXML XML part
      timeout: 60, # seconds, wall clock (sandbox only)
      memory_limit: 1024 * MEGABYTE, # RLIMIT_DATA for the sandbox child; nil disables
      cpu_limit: 60, # seconds, RLIMIT_CPU for the sandbox child; nil disables
    }.freeze

    def initialize(**options)
      unknown = options.keys - DEFAULTS.keys
      raise ArgumentError, "unknown policy option(s): #{unknown.join(', ')}" if unknown.any?

      merged = DEFAULTS.merge(options)
      # The sandbox deadline needs a real number; nil here used to raise TypeError mid-check.
      raise ArgumentError, 'timeout must be a positive number' unless merged[:timeout].is_a?(Numeric) && merged[:timeout].positive?

      merged[:allowed_types] = Array(merged[:allowed_types]).map(&:to_s).freeze
      merged[:allow_unverifiable] = Array(merged[:allow_unverifiable]).map(&:to_s).freeze
      super(**merged)
    end

    def permitted_type?(type)
      allowed_types.include?(type) || allow_unverifiable.include?(type)
    end
  end
end
