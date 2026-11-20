# frozen_string_literal: true

module UploadInspector
  # Outcome of an inspection. +reason+ is a Symbol (nil when safe), +detail+ a human-readable hint.
  # +would_reject+ is set in report mode: the reason the file would have been rejected.
  Result = Data.define(:safe, :reason, :detail, :detected_type, :would_reject) do
    def initialize(safe:, reason:, detail:, detected_type:, would_reject: nil) = super

    def self.accept(detected_type)
      new(safe: true, reason: nil, detail: nil, detected_type:)
    end

    def self.reject(reason, detail = nil, detected_type: nil)
      new(safe: false, reason: reason.to_sym, detail:, detected_type:)
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

  # Shared helper for inspectors.
  module Rejectable
  private

    def reject!(reason, detail = nil)
      raise Rejection.new(reason, detail)
    end
  end
end
