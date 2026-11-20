# frozen_string_literal: true

module UploadInspector
  # Ready-made allowed_types lists, all structurally verified. Combine them freely:
  #
  #   UploadInspector.check(file, allowed_types: Presets::IMAGES + Presets::DOCUMENTS)
  module Presets
    PDF = %w[application/pdf].freeze
    OFFICE = %w[
      application/vnd.openxmlformats-officedocument.wordprocessingml.document
      application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
      application/vnd.openxmlformats-officedocument.presentationml.presentation
    ].freeze
    DOCUMENTS = (PDF + OFFICE).freeze
    IMAGES = %w[image/png image/jpeg image/gif image/webp image/heic image/heif image/avif].freeze
    SVG = %w[image/svg+xml].freeze
    MEDIA = %w[video/mp4 video/quicktime].freeze
    TEXT = %w[text/plain text/csv text/tab-separated-values].freeze
  end
end
