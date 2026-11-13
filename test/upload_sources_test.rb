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
    Head = Struct.new(:content_length, :etag)
    attr_reader :calls

    def initialize(bytes, etag: '"abc"')
      @bytes = bytes
      @etag = etag
      @calls = []
    end

    def head_object(**args)
      @calls << [:head_object, args]
      Head.new(@bytes.bytesize, @etag)
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
end
