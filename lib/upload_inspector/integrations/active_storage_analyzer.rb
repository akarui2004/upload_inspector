# frozen_string_literal: true

require 'active_storage'

module UploadInspector
  # Inspects every Active Storage blob once it is uploaded, direct uploads included (which the
  # validator never sees), and records the verdict in the blob's metadata:
  #
  #   # config/initializers/upload_inspector.rb
  #   UploadInspector::ActiveStorageAnalyzer.options = { allowed_types: UploadInspector::Presets::DOCUMENTS }
  #   Rails.application.config.active_storage.analyzers.prepend UploadInspector::ActiveStorageAnalyzer
  #
  #   blob.metadata[:upload_inspector] # => { "safe" => false, "reason" => "pdf_active_content", ... }
  #
  # Active Storage runs one analyzer per blob, so this one accepts every blob and merges in the
  # metadata of the analyzer that would have run otherwise (image dimensions, video duration).
  #
  # To react to an unsafe blob (notify, flag the record, purge), subclass, override #on_unsafe
  # and register the subclass. It runs before Active Storage saves the metadata.
  #
  #   class FlagUnsafeUploads < UploadInspector::ActiveStorageAnalyzer
  #     def on_unsafe(result)
  #       blob.attachments.each { |attachment| attachment.purge_later }
  #     end
  #   end
  class ActiveStorageAnalyzer < ActiveStorage::Analyzer
    class << self
      # UploadInspector.check keywords (Policy options, sandbox:, scanner:, ...); subclasses
      # use their parent's unless given their own.
      attr_writer :options

      def options = @options || (equal?(ActiveStorageAnalyzer) ? {} : superclass.options)
      def accept?(_blob) = true
    end

    def metadata
      result = download_blob_to_tempfile do |file|
        UploadInspector.check(file, filename: blob.filename.to_s, **self.class.options)
      end
      verdict = { safe: result.safe?, reason: result.reason&.to_s, detail: result.detail,
                  detected_type: result.detected_type, would_reject: result.would_reject&.to_s, }.compact
      on_unsafe(result) unless result.safe?
      next_analyzer_metadata.merge(upload_inspector: verdict)
    end

    # Called with the Result when the blob is unsafe (never in mode: :report); +blob+ is the blob.
    def on_unsafe(result); end

    private

    def next_analyzer_metadata
      analyzer = ActiveStorage.analyzers.find { |klass| !(klass <= ActiveStorageAnalyzer) && klass.accept?(blob) }
      analyzer ? analyzer.new(blob).metadata : {}
    end
  end
end
