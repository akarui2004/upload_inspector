# frozen_string_literal: true

require 'active_job'

module UploadInspector
  # Inspects the Active Storage attachments of a record in the background and purges the
  # unsafe ones. Fits direct uploads and large files, which should not be checked in a request.
  #
  #   # after record.save (the file is in storage once save returns)
  #   UploadInspector::InspectJob.perform_later(record, 'document', allowed_types: %w[application/pdf])
  #
  # Options are UploadInspector.check keywords (mode: :report never purges); purge: false keeps unsafe files (e.g. for
  # review). To react to a rejection (notify the uploader, flag the record), subclass and
  # override #on_unsafe, then enqueue the subclass. To scan for malware, override #scanner
  # (a scanner object cannot be a job argument). When the scanner cannot scan an attachment,
  # that one is kept and, once every other attachment was handled, the job raises
  # Scanners::Error (retry it with retry_on) instead of purging over an outage.
  class InspectJob < ActiveJob::Base
    def perform(record, name, purge: true, **options)
      attached = record.public_send(name)
      attachments = attached.respond_to?(:attachments) ? attached.attachments.to_a : [attached.attachment].compact
      # A failing scan must not stop the others: an unsafe file further on is still purged.
      unscanned = attachments.filter_map do |attachment|
        result = UploadInspector.check(attachment, scanner:, **options)
        next if result.safe?
        next result.detail if result.reason == :scanner_failed

        attachment.purge if purge
        on_unsafe(record, name, attachment, result)
        nil
      end
      raise Scanners::Error, unscanned.uniq.join('; ') if unscanned.any?
    end

    # Malware scanner for UploadInspector.check (see UploadInspector::Scanners), nil for none.
    def scanner; end

    # Called for each unsafe attachment, after it was purged (its filename and other
    # attributes are still readable). result.reason / result.message say why.
    def on_unsafe(record, name, attachment, result); end
  end
end
