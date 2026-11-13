# frozen_string_literal: true

require 'active_job'

module UploadInspector
  # Inspects the Active Storage attachments of a record in the background and purges the
  # unsafe ones. Fits direct uploads and large files, which should not be checked in a request.
  #
  #   # after record.save (the file is in storage once save returns)
  #   UploadInspector::InspectJob.perform_later(record, 'document', allowed_types: %w[application/pdf])
  #
  # Options are UploadInspector.check keywords; purge: false keeps unsafe files (e.g. for
  # review). To react to a rejection (notify the uploader, flag the record), subclass and
  # override #on_unsafe, then enqueue the subclass.
  class InspectJob < ActiveJob::Base
    def perform(record, name, purge: true, **options)
      attached = record.public_send(name)
      attachments = attached.respond_to?(:attachments) ? attached.attachments.to_a : [attached.attachment].compact
      attachments.each do |attachment|
        result = UploadInspector.check(attachment, **options)
        next if result.safe?

        attachment.purge if purge
        on_unsafe(record, name, attachment, result)
      end
    end

    # Called for each unsafe attachment, after it was purged (its filename and other
    # attributes are still readable). result.reason / result.message say why.
    def on_unsafe(record, name, attachment, result); end
  end
end
