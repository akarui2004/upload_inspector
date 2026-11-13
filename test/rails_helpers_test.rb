# frozen_string_literal: true

require 'test_helper'
require 'logger'
require 'active_job'
require 'active_model'

ActiveJob::Base.logger = Logger.new(nil)

# Validator and job against objects shaped like Active Storage's, without a Rails app.
class RailsHelpersTest < Minitest::Test
  include FixtureBuilder

  UploadedFile = Struct.new(:original_filename, :path)
  CreateOne = Struct.new(:attachable)
  CreateMany = Struct.new(:attachables)

  # A blob-backed attachment: open yields a local copy, purge deletes it.
  class FakeAttachment
    attr_reader :filename, :purged

    def initialize(filename, path)
      @filename = filename
      @path = path
    end

    def open = File.open(@path, 'rb') { |file| yield file }
    def purge = @purged = true
  end

  class Document
    include ActiveModel::Model
    attr_accessor :file, :attachment_changes

    validates :file, upload_inspector: { allowed_types: %w[application/pdf], sandbox: false }
  end

  def valid_document(**attributes)
    document = Document.new(**attributes)
    [document.valid?, document]
  end

  def test_validator_accepts_and_rejects_plain_uploads
    assert valid_document(file: UploadedFile.new('a.pdf', write_file('RackMultipart1', clean_pdf))).first

    valid, document = valid_document(file: UploadedFile.new('a.zip', write_file('RackMultipart2', clean_pdf)))
    refute valid
    assert_equal [{ error: :extension_mismatch }], document.errors.details[:file]
    assert_equal ['File does not match its file extension'], document.errors.full_messages
  end

  def test_validator_reads_pending_active_storage_attachables
    io = StringIO.new(clean_pdf)
    assert valid_document(attachment_changes: { 'file' => CreateOne.new({ io:, filename: 'a.pdf' }) }).first
    assert_equal 0, io.pos, 'IO must be rewound so Active Storage stores the whole file'

    many = CreateMany.new([UploadedFile.new('a.pdf', write_file('ok', clean_pdf)), { io: StringIO.new('x'), filename: 'b.pdf' }])
    valid, document = valid_document(attachment_changes: { 'file' => many })
    refute valid
    assert_equal [:unverifiable_type], document.errors.details[:file].map { _1[:error] }
  end

  def test_validator_never_treats_strings_as_paths
    assert valid_document(file: write_file('secret.pdf', 'not a pdf')).first
    assert valid_document(attachment_changes: { 'file' => CreateOne.new('signed-blob-id') }).first
  end

  def test_messages_use_i18n_overrides
    I18n.backend.store_translations(:en, upload_inspector: { errors: { extension_mismatch: 'has the wrong extension' } })
    assert_equal 'has the wrong extension', UploadInspector::Result.reject(:extension_mismatch).message
    assert_equal 'contains content that is not allowed', UploadInspector::Result.reject(:something_new).message
    assert_nil UploadInspector::Result.accept('application/pdf').message
  ensure
    I18n.backend.reload!
  end

  # Records rejections instead of notifying anyone.
  class RecordingJob < UploadInspector::InspectJob
    def on_unsafe(record, name, attachment, result) = record.rejected << [name, attachment.filename, result.reason]
  end

  Record = Struct.new(:documents, :rejected)
  Many = Struct.new(:attachments)
  One = Struct.new(:attachment)

  def test_job_purges_unsafe_attachments_and_calls_hook
    good = FakeAttachment.new('a.pdf', write_file('good', clean_pdf))
    bad = FakeAttachment.new('b.pdf', write_file('bad', 'not a pdf'))
    record = Record.new(Many.new([good, bad]), [])

    RecordingJob.perform_now(record, 'documents', allowed_types: %w[application/pdf], sandbox: false)
    refute good.purged
    assert bad.purged
    assert_equal [['documents', 'b.pdf', :unverifiable_type]], record.rejected
  end

  def test_job_handles_has_one_and_keeps_files_when_asked
    bad = FakeAttachment.new('b.pdf', write_file('bad', 'not a pdf'))
    UploadInspector::InspectJob.perform_now(Record.new(One.new(bad)), 'documents', purge: false, sandbox: false)
    refute bad.purged
    UploadInspector::InspectJob.perform_now(Record.new(One.new(nil)), 'documents', sandbox: false)
  end
end
