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

    GUARDDUTY_TAG = 'GuardDutyMalwareScanStatus'

    # Returns a Result. S3/network errors (missing key, access denied, timeouts) raise, so a
    # job retries instead of treating an outage as a hostile file.
    #
    # +require_guardduty_tag+ reads the tag GuardDuty Malware Protection for S3 writes on the
    # object (needs s3:GetObjectTagging) before downloading it: THREATS_FOUND is
    # :malware_detected, NO_THREATS_FOUND goes on to the inspection, any other status
    # (UNSUPPORTED, ACCESS_DENIED, FAILED) is :scanner_failed (accepted with +scanner_fail_open+).
    # No tag yet raises Scanners::Pending, so a job retries once the scan is done.
    # The tag is only as trustworthy as who may write it: the bucket policy must deny setting
    # it to every principal but GuardDuty's role (see README), or an uploader can tag its own
    # object NO_THREATS_FOUND.
    def check(client:, bucket:, key:, filename:, version_id:, sandbox:, policy:, payload: {}, scanner: nil,
              scanner_fail_open: false, require_guardduty_tag: false)
      object = { bucket:, key:, version_id: }.compact
      head = client.head_object(**object)
      # Versioned bucket: tags and bytes are read from the version that was checked.
      object[:version_id] ||= head.version_id if head.respond_to?(:version_id) && head.version_id
      size = head.content_length.to_i
      return Result.reject(:too_large, "#{size} bytes") if size > policy.max_file_size

      # Read after the HEAD: if the object is replaced in between, the ETag-pinned download fails.
      if require_guardduty_tag
        rejection = guardduty_rejection(client, object, fail_open: scanner_fail_open)
        return rejection if rejection
      end

      Dir.mktmpdir('upload_inspector_s3') do |dir|
        path = File.join(dir, 'object')
        # if_match pins the download to the object that was size-checked: an overwrite
        # in between fails the download instead of slipping a bigger file through.
        client.get_object(**object, if_match: head.etag, response_target: path)
        UploadInspector.inspect_source(path, filename: filename || File.basename(key), sandbox:, policy:, payload:,
                                             scanner:, scanner_fail_open:)
      end
    end

    def guardduty_rejection(client, object, fail_open:)
      tags = client.get_object_tagging(**object).tag_set
      status = tags.find { |tag| tag.key == GUARDDUTY_TAG }&.value
      case status
      when nil then raise Scanners::Pending, "no #{GUARDDUTY_TAG} tag on s3://#{object[:bucket]}/#{object[:key]} yet"
      when 'NO_THREATS_FOUND' then nil
      when 'THREATS_FOUND' then Result.reject(:malware_detected, 'GuardDuty: THREATS_FOUND')
      else Result.reject(:scanner_failed, "GuardDuty: #{status}") unless fail_open
      end
    end
  end
end
