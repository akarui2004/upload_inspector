# frozen_string_literal: true

require 'test_helper'
require 'stringio'

# Upload sources other than a plain path (Rails uploads, Active Storage, IO) and S3 objects.
class UploadSourcesTest < Minitest::Test
  include FixtureBuilder

  # Shapes of ActionDispatch::Http::UploadedFile and ActiveStorage::Blob, without Rails.
  UploadedFile = Struct.new(:original_filename, :path)
  Blob = Struct.new(:filename, :bytes, :tmp) do
    def open
      File.binwrite(tmp, bytes)
      yield File.open(tmp, 'rb')
    end
  end

  # Records calls; mimics Aws::S3::Client#head_object / #get_object(response_target:).
  class FakeS3
    Head = Struct.new(:content_length, :etag, :version_id)
    Tag = Struct.new(:key, :value)
    Tagging = Struct.new(:tag_set)
    attr_reader :calls

    def initialize(bytes, etag: '"abc"', tags: {}, version_id: nil)
      @bytes = bytes
      @etag = etag
      @version_id = version_id
      @tags = tags
      @calls = []
    end

    def get_object_tagging(**args)
      @calls << [:get_object_tagging, args]
      Tagging.new(@tags.map { |key, value| Tag.new(key, value) })
    end

    def head_object(**args)
      @calls << [:head_object, args]
      Head.new(@bytes.bytesize, @etag, @version_id)
    end

    def get_object(response_target:, **args)
      @calls << [:get_object, args]
      File.binwrite(response_target, @bytes)
    end
  end

  def check(source, **options)
    UploadInspector.check(source, sandbox: false, **options)
  end

  def test_rails_uploaded_file_uses_original_filename
    upload = UploadedFile.new('design.pdf', write_file('RackMultipart123', clean_pdf))
    assert check(upload).safe?
    assert_equal :extension_mismatch, check(UploadedFile.new('design.zip', upload.path)).reason
  end

  def test_filename_keyword_overrides_source_name
    upload = UploadedFile.new('design.pdf', write_file('RackMultipart123', clean_pdf))
    assert_equal :extension_mismatch, check(upload, filename: 'design.zip').reason
  end

  def test_file_and_pathname_need_a_filename
    path = write_file('a.pdf', clean_pdf)
    File.open(path, 'rb') { |file| assert check(file, filename: 'a.pdf').safe? }
    assert check(Pathname(path), filename: 'a.pdf').safe?
    assert_raises(ArgumentError) { check(path) }
  end

  def test_active_storage_blob
    blob = Blob.new('design.pdf', clean_pdf, tmp_path('blob'))
    assert check(blob).safe?
  end

  def test_oversized_blob_is_not_downloaded
    blob = Blob.new('design.pdf', clean_pdf, tmp_path('blob'))
    blob.define_singleton_method(:byte_size) { bytes.bytesize }
    blob.define_singleton_method(:open) { flunk 'blob downloaded' }
    assert_equal :too_large, check(blob, max_file_size: 10).reason
  end

  def test_plain_io_is_copied_with_a_size_cap
    assert check(StringIO.new(clean_pdf), filename: 'a.pdf').safe?
    assert_equal :too_large, check(StringIO.new(clean_pdf), filename: 'a.pdf', max_file_size: 10).reason
  end

  def test_unsupported_source_raises
    assert_raises(ArgumentError) { check(42, filename: 'a.pdf') }
  end

  def test_sandboxed_upload
    upload = UploadedFile.new('design.pdf', write_file('RackMultipart123', clean_pdf))
    assert UploadInspector.check(upload).safe?
  end

  def test_s3_object_pinned_to_checked_version
    s3 = FakeS3.new(clean_pdf)
    result = UploadInspector.check_s3(client: s3, bucket: 'b', key: 'tmp/x/design.pdf', version_id: 'v1', sandbox: false)
    assert result.safe?, result.detail
    assert_equal [[:head_object, { bucket: 'b', key: 'tmp/x/design.pdf', version_id: 'v1' }],
                  [:get_object, { bucket: 'b', key: 'tmp/x/design.pdf', version_id: 'v1', if_match: '"abc"' }]], s3.calls
  end

  def test_s3_name_comes_from_key_unless_given
    s3 = FakeS3.new(clean_pdf)
    assert_equal :extension_mismatch, UploadInspector.check_s3(client: s3, bucket: 'b', key: 'x.zip', sandbox: false).reason
    assert UploadInspector.check_s3(client: s3, bucket: 'b', key: 'uuid', filename: 'x.pdf', sandbox: false).safe?
  end

  def test_s3_oversized_object_is_not_downloaded
    s3 = FakeS3.new(clean_pdf)
    result = UploadInspector.check_s3(client: s3, bucket: 'b', key: 'x.pdf', max_file_size: 10)
    assert_equal :too_large, result.reason
    assert_equal [:head_object], s3.calls.map(&:first)
  end

  def guardduty(status, **options)
    tags = status ? { 'other' => 'x', 'GuardDutyMalwareScanStatus' => status } : {}
    s3 = FakeS3.new(clean_pdf, tags:)
    result = UploadInspector.check_s3(client: s3, bucket: 'b', key: 'x.pdf', sandbox: false,
                                      require_guardduty_tag: true, **options)
    [result, s3.calls.map(&:first)]
  end

  def test_s3_guardduty_tag
    result, calls = guardduty('NO_THREATS_FOUND')
    assert result.safe?
    assert_equal %i[head_object get_object_tagging get_object], calls

    result, calls = guardduty('THREATS_FOUND')
    assert_equal [:malware_detected, 'GuardDuty: THREATS_FOUND'], [result.reason, result.detail]
    refute_includes calls, :get_object # infected objects are not downloaded

    assert_equal :scanner_failed, guardduty('UNSUPPORTED').first.reason
    assert guardduty('ACCESS_DENIED', scanner_fail_open: true).first.safe?
    assert_raises(UploadInspector::Scanners::Pending) { guardduty(nil) }
    refute_includes FakeS3.new(clean_pdf).tap { |s3|
      UploadInspector.check_s3(client: s3, bucket: 'b', key: 'x.pdf', sandbox: false)
    }.calls.map(&:first), :get_object_tagging
  end

  def test_s3_versioned_object_tags_and_bytes_from_the_checked_version
    s3 = FakeS3.new(clean_pdf, tags: { 'GuardDutyMalwareScanStatus' => 'NO_THREATS_FOUND' }, version_id: 'v7')
    assert UploadInspector.check_s3(client: s3, bucket: 'b', key: 'x.pdf', sandbox: false, require_guardduty_tag: true).safe?
    assert_equal [{ bucket: 'b', key: 'x.pdf' }, { bucket: 'b', key: 'x.pdf', version_id: 'v7' },
                  { bucket: 'b', key: 'x.pdf', version_id: 'v7', if_match: '"abc"' },], s3.calls.map(&:last)
  end
end
