# frozen_string_literal: true

require 'tmpdir'

module UploadInspector
  # Inspects an object uploaded straight to S3 (presigned PUT/POST), so it never passed
  # through the app. The client is duck-typed: anything with Aws::S3::Client's +head_object+
  # and +get_object+ works, so this gem does not depend on aws-sdk-s3.
  #
  # The Content-Type and size the browser declared are ignored: the presigned uploader
  # controls them. Only the downloaded bytes are judged.
  module S3
    module_function

    # Returns a Result. S3/network errors (missing key, access denied, timeouts) raise, so a
    # job retries instead of treating an outage as a hostile file.
    def check(client:, bucket:, key:, filename:, version_id:, sandbox:, policy:)
      object = { bucket:, key:, version_id: }.compact
      head = client.head_object(**object)
      size = head.content_length.to_i
      return Result.reject(:too_large, "#{size} bytes") if size > policy.max_file_size

      Dir.mktmpdir('upload_inspector_s3') do |dir|
        path = File.join(dir, 'object')
        # if_match pins the download to the object that was size-checked: an overwrite
        # in between fails the download instead of slipping a bigger file through.
        client.get_object(**object, if_match: head.etag, response_target: path)
        UploadInspector.check(path, filename: filename || File.basename(key), sandbox:, **policy.to_h)
      end
    end
  end
end
