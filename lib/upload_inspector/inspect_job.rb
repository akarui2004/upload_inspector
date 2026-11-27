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
  # (a scanner object cannot be a job argument); when the scanner cannot scan, the job raises
  # Scanners::Error (retry it with retry_on) instead of purging over an outage.
  class InspectJob < ActiveJob::Base
    def perform(record, name, purge: true, **options)
      attached = record.public_send(name)
      attachments = attached.respond_to?(:attachments) ? attached.attachments.to_a : [attached.attachment].compact
      attachments.each do |attachment|
        result = UploadInspector.check(attachment, scanner:, **options)
        next if result.safe?
        raise Scanners::Error, result.detail if result.reason == :scanner_failed

        attachment.purge if purge
        on_unsafe(record, name, attachment, result)
      end
    end

    # Malware scanner for UploadInspector.check (see UploadInspector::Scanners), nil for none.
    def scanner; end

    # Called for each unsafe attachment, after it was purged (its filename and other
    # attributes are still readable). result.reason / result.message say why.
    def on_unsafe(record, name, attachment, result); end
  end
end
