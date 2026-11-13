# frozen_string_literal: true

require 'active_model'

# Rejects unsafe files uploaded through the request, before the record is saved:
#
#   validates :document, upload_inspector: { allowed_types: %w[application/pdf] }
#
# Works for Active Storage attachments (has_one_attached / has_many_attached) and plain
# attributes holding an uploaded file or IO. Options are UploadInspector.check keywords
# (Policy options, sandbox:). The error type is the rejection reason (errors.details shows
# e.g. { error: :pdf_active_content }) with the message from UploadInspector::Messages.
#
# The check runs inside the request: keep it to small files. Blobs uploaded directly to
# storage (signed ids, direct uploads) are not here yet; check those with InspectJob.
class UploadInspectorValidator < ActiveModel::EachValidator
  CHECK_OPTIONS = [*UploadInspector::Policy::DEFAULTS.keys, :sandbox].freeze

  def validate_each(record, attribute, value)
    uploads(record, attribute, value).each do |source, filename|
      result = UploadInspector.check(source, filename:, **options.slice(*CHECK_OPTIONS))
      record.errors.add(attribute, result.reason, message: result.message) unless result.safe?
    end
  end

  private

  # [source, filename] pairs for files that arrived with this request.
  def uploads(record, attribute, value)
    change = record.attachment_changes&.[](attribute.to_s) if record.respond_to?(:attachment_changes)
    pending = if change
                change.respond_to?(:attachables) ? change.attachables : [change.attachable]
              else
                value.is_a?(Array) ? value : [value]
              end
    pending.filter_map do |attachable|
      if attachable.is_a?(Hash) # attach(io:, filename:)
        [attachable.fetch(:io), attachable.fetch(:filename).to_s]
      elsif attachable.respond_to?(:original_filename) || attachable.respond_to?(:read)
        [attachable, nil]
      end
      # Anything else (a blob, a signed blob id, a String) is not a request upload. Strings
      # are never treated as paths: a form value must not make the server read its own files.
    end
  end
end
