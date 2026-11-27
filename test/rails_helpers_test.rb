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

  class ShadowDocument
    include ActiveModel::Model
    attr_accessor :file

    validates :file, upload_inspector: { allowed_types: %w[application/pdf], sandbox: false, mode: :report }
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

  def test_report_mode_never_blocks_and_publishes_the_check
    events = []
    subscriber = ActiveSupport::Notifications.subscribe('check.upload_inspector') { events << _1.payload }
    upload = UploadedFile.new('a.zip', write_file('RackMultipart3', clean_pdf))
    assert ShadowDocument.new(file: upload).valid?
    assert_equal({ mode: :report, filename_ext: '.zip', size: clean_pdf.bytesize, reason: nil,
                   would_reject: :extension_mismatch, detected_type: 'application/pdf', },
                 events.last)
  ensure
    ActiveSupport::Notifications.unsubscribe(subscriber)
  end

  def test_sanitize_publishes_its_own_event
    events = []
    subscriber = ActiveSupport::Notifications.subscribe('sanitize.upload_inspector') { events << _1.payload }
    UploadInspector.sanitize(write_file('upload', clean_pdf), filename: 'a.pdf', to: tmp_path('clean.pdf'), sandbox: false)
    assert_equal({ filename_ext: '.pdf', size: clean_pdf.bytesize, reason: :sanitize_unsupported,
                   detected_type: 'application/pdf', }, events.last)
  ensure
    ActiveSupport::Notifications.unsubscribe(subscriber)
  end

  # Fails every scan, as when clamd is down.
  class DownScanner
    def scan(_path) = raise(UploadInspector::Scanners::Error, 'clamd down')
  end

  class ScanningJob < RecordingJob
    def scanner = DownScanner.new
  end

  class ScannedDocument
    include ActiveModel::Model
    attr_accessor :file

    validates :file, upload_inspector: { allowed_types: %w[application/pdf], sandbox: false, scanner: DownScanner.new }
  end

  def test_validator_passes_the_scanner
    document = ScannedDocument.new(file: UploadedFile.new('a.pdf', write_file('RackMultipart4', clean_pdf)))
    refute document.valid?
    assert_equal [{ error: :scanner_failed }], document.errors.details[:file]
  end

  def test_job_retries_instead_of_purging_when_the_scanner_fails
    good = FakeAttachment.new('a.pdf', write_file('good', clean_pdf))
    bad = FakeAttachment.new('b.pdf', write_file('bad', 'not a pdf'))
    record = Record.new(Many.new([good, bad]), [])
    error = assert_raises(UploadInspector::Scanners::Error) { ScanningJob.perform_now(record, 'documents', sandbox: false) }
    assert_equal 'UploadInspector::Scanners::Error: clamd down', error.message
    refute good.purged
    assert bad.purged # handled although the scan before it failed
    assert_equal [['documents', 'b.pdf', :unverifiable_type]], record.rejected
    record.rejected.clear
    ScanningJob.perform_now(record, 'documents', sandbox: false, scanner_fail_open: true)
    refute good.purged
  end

  def test_scan_publishes_its_own_event
    events = []
    subscriber = ActiveSupport::Notifications.subscribe('scan.upload_inspector') { events << _1.payload }
    UploadInspector.check(write_file('s.pdf', clean_pdf), filename: 's.pdf', sandbox: false, scanner: DownScanner.new)
    assert_equal({ scanner: 'RailsHelpersTest::DownScanner', reason: :scanner_failed,
                   detail: 'UploadInspector::Scanners::Error: clamd down', }, events.last)
  ensure
    ActiveSupport::Notifications.unsubscribe(subscriber)
  end
end
