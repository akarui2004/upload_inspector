# frozen_string_literal: true

require_relative 'integration_helper'
ACTIVE_STORAGE = IntegrationHelper.load('active_storage', 'active_storage/analyzer')

class ActiveStorageAnalyzerTest < Minitest::Test
  include FixtureBuilder

  # The parts of ActiveStorage::Blob an analyzer uses.
  Blob = Struct.new(:filename, :path) do
    def open(tmpdir:) = File.open(path, 'rb') { |file| yield file }
  end

  def setup
    skip 'needs the activestorage gem (Gemfile group :integration)' unless ACTIVE_STORAGE
    @analyzers = ActiveStorage.analyzers
    UploadInspector::ActiveStorageAnalyzer.options = { allowed_types: %w[application/pdf], sandbox: false }
    dimensions = Class.new(ActiveStorage::Analyzer) do
      def self.accept?(blob) = blob.filename.end_with?('.pdf')
      def metadata = { pages: 0 }
    end
    ActiveStorage.analyzers = [UploadInspector::ActiveStorageAnalyzer, dimensions]
  end

  def teardown
    ActiveStorage.analyzers = @analyzers if ACTIVE_STORAGE
    UploadInspector::ActiveStorageAnalyzer.options = nil if ACTIVE_STORAGE
    super
  end

  def analyze(name, bytes)
    UploadInspector::ActiveStorageAnalyzer.new(Blob.new(name, write_file(name, bytes))).metadata
  end

  def test_records_the_verdict_and_keeps_the_next_analyzer_metadata
    assert UploadInspector::ActiveStorageAnalyzer.accept?(Blob.new('x.bin'))
    assert_equal({ pages: 0, upload_inspector: { safe: true, detected_type: 'application/pdf' } },
                 analyze('a.pdf', clean_pdf))
    assert_equal({ upload_inspector: { safe: false, reason: 'type_not_allowed', detail: 'text/plain',
                                       detected_type: 'text/plain', }, },
                 analyze('a.txt', 'hi'))
  end

  if ACTIVE_STORAGE
    # Records the unsafe blobs it sees.
    class RecordingAnalyzer < UploadInspector::ActiveStorageAnalyzer
      class << self
        attr_accessor :unsafe
      end

      def on_unsafe(result) = (self.class.unsafe ||= []) << [blob.filename, result.reason]
    end
  end

  def test_subclass_hook_sees_unsafe_blobs_and_inherits_options
    %w[a.pdf b.txt].each do |name|
      RecordingAnalyzer.new(Blob.new(name, write_file(name, name.end_with?('.pdf') ? clean_pdf : 'hi'))).metadata
    end
    assert_equal [['b.txt', :type_not_allowed]], RecordingAnalyzer.unsafe
  end

  Stored = Struct.new(:analyzed?, :metadata)

  def test_safe_needs_an_analyzed_blob_with_a_safe_verdict
    analyzer = UploadInspector::ActiveStorageAnalyzer
    assert analyzer.safe?(Stored.new(true, { 'upload_inspector' => { 'safe' => true } }))
    assert analyzer.safe?(Stored.new(true, { upload_inspector: { safe: true } }))
    refute analyzer.safe?(Stored.new(false, { 'upload_inspector' => { 'safe' => true } })) # client-sent, pending
    refute analyzer.safe?(Stored.new(true, { 'upload_inspector' => { 'safe' => 'true' } }))
    refute analyzer.safe?(Stored.new(true, {}))
  end
end
