# frozen_string_literal: true

module UploadInspector
  # Outcome of an inspection. +reason+ is a Symbol (nil when safe), +detail+ a human-readable hint.
  # +would_reject+ is set in report mode: the reason the file would have been rejected.
  # +links+ lists the web/mail URLs found in the file (PDF, Office, SVG, RTF), at most
  # LinkCollector::MAX_LINKS, e.g. to check them against a URL reputation service.
  # +sanitized_path+ is where UploadInspector.sanitize wrote the cleaned file (nil otherwise).
  Result = Data.define(:safe, :reason, :detail, :detected_type, :would_reject, :links, :sanitized_path) do
    def initialize(safe:, reason:, detail:, detected_type:, would_reject: nil, links: [], sanitized_path: nil) = super(
      safe:, reason:, detail:, detected_type:, would_reject:, links: links.dup.freeze, sanitized_path:
    )

    def self.accept(detected_type, links: [])
      new(safe: true, reason: nil, detail: nil, detected_type:, links:)
    end

    def self.reject(reason, detail = nil, detected_type: nil, links: [])
      new(safe: false, reason: reason.to_sym, detail:, detected_type:, links:)
    end

    def safe? = safe

    # Report mode: accept, but keep why the file would have been rejected.
    def reported = safe ? self : with(safe: true, reason: nil, would_reject: reason)

    # End-user message for the rejection (see Messages), nil when safe.
    def message = reason && Messages.for(reason)
  end

  # Raised internally by inspectors; converted to a rejected Result at the boundary.
  class Rejection < StandardError
    attr_reader :reason, :detail

    def initialize(reason, detail = nil)
      @reason = reason
      @detail = detail
      super([reason, detail].compact.join(': '))
    end
  end

  # Records URLs for Result#links into the inspector's @links array.
  module LinkCollector
    MAX_LINKS = 100

  private

    def add_link(url)
      return if @links.size >= MAX_LINKS

      url = url.to_s.dup.force_encoding(Encoding::UTF_8).scrub # the sandbox returns JSON
      @links << url unless @links.include?(url)
    end
  end

  # Shared helper for inspectors.
  module Rejectable
  private

    def reject!(reason, detail = nil)
      raise Rejection.new(reason, detail)
    end
  end
end
