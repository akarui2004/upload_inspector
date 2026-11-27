# frozen_string_literal: true

require 'test_helper'
require 'socket'

# Malware scanner hook and adapters, against a fake clamd speaking INSTREAM and shell commands.
class ScannersTest < Minitest::Test
  include FixtureBuilder

  # Built at runtime so this source file is not itself flagged by antivirus.
  EICAR = ['X5O!P%@AP[4\\PZX54(P^)7CC)7}$', 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'].join

  # Answers like clamd: "Eicar-Test-Signature FOUND" when the stream holds EICAR, else OK.
  # Records each stream so tests can see what was (or was not) sent.
  class FakeClamd
    attr_reader :streams

    def initialize(server, reply: nil)
      @server = server
      @reply = reply
      @streams = []
      @thread = Thread.new { loop { serve(@server.accept) } }
    end

    def stop
      @thread.kill
      @server.close
    end

    private

    def serve(client)
      raise "bad command #{client.read(10).inspect}" unless client.read(10) == "zINSTREAM\0"

      data = +''
      while (length = client.read(4).unpack1('N')).positive?
        data << client.read(length)
      end
      @streams << data
      client.write(@reply || (data.include?(EICAR) ? "stream: Eicar-Test-Signature FOUND\0" : "stream: OK\0"))
    ensure
      client.close
    end
  end

  def setup
    @clamd = FakeClamd.new(TCPServer.new('127.0.0.1', 0))
  end

  def teardown
    @clamd&.stop
  end

  def clamav(**options) = UploadInspector::Scanners::ClamAV.new(host: '127.0.0.1', port: port, **options)
  def port = @clamd.instance_variable_get(:@server).addr[1]

  def check(bytes, filename: 'note.txt', **options)
    UploadInspector.check(write_file(filename, bytes), filename:, sandbox: false,
                                                       allowed_types: %w[text/plain application/pdf], **options)
  end

  def test_eicar_is_malware_detected
    result = check(EICAR, scanner: clamav)
    assert_equal :malware_detected, result.reason
    assert_equal 'Eicar-Test-Signature', result.detail
    assert_equal 'text/plain', result.detected_type
    assert_equal 'contains malware', result.message
  end

  def test_clean_file_is_streamed_in_chunks_and_accepted
    big = "#{'a' * 99} \n" * 2000 # 200 KB: several 64 KB chunks
    assert check(big, scanner: clamav).safe?
    assert_equal [big], @clamd.streams
  end

  def test_unix_socket
    dir = Dir.mktmpdir
    socket = File.join(dir, 'clamd.ctl')
    unix = FakeClamd.new(UNIXServer.new(socket))
    assert_equal :malware_detected, check(EICAR, scanner: UploadInspector::Scanners::ClamAV.new(socket:)).reason
  ensure
    unix&.stop
    FileUtils.rm_rf(dir)
  end

  def test_structural_rejection_is_not_scanned
    assert_equal :extension_mismatch, check(clean_pdf, filename: 'x.txt', scanner: clamav).reason
    assert_empty @clamd.streams
  end

  def test_clamd_down_fails_closed_unless_fail_open
    down = clamav
    @clamd.stop
    @clamd = nil
    result = check('hello', scanner: down)
    assert_equal :scanner_failed, result.reason
    assert_match(/ECONNREFUSED/, result.detail)
    assert check('hello', scanner: down, scanner_fail_open: true).safe?
  end

  def test_clamd_errors_and_size_limit_fail
    @clamd.stop
    @clamd = FakeClamd.new(TCPServer.new('127.0.0.1', 0), reply: "INSTREAM size limit exceeded. ERROR\0")
    assert_equal 'Scanners::Error: clamd: INSTREAM size limit exceeded. ERROR',
                 check('hello', scanner: clamav).detail.delete_prefix('UploadInspector::')
    assert_match(/exceeds max_stream/, check('hello world', scanner: clamav(max_stream: 5)).detail)
  end

  def test_silent_clamd_times_out
    silent = TCPServer.new('127.0.0.1', 0)
    scanner = UploadInspector::Scanners::ClamAV.new(host: '127.0.0.1', port: silent.addr[1], timeout: 0.2)
    accepted = Thread.new { silent.accept } # never replies
    assert_equal :scanner_failed, check('hello', scanner:).reason
  ensure
    accepted&.kill
    silent&.close
  end

  def test_report_mode_keeps_the_scanner_reason
    result = check(EICAR, scanner: clamav, mode: :report)
    assert result.safe?
    assert_equal :malware_detected, result.would_reject
  end

  # Any object answering scan(path) works; odd answers fail closed.
  def test_custom_scanner_contract
    odd = Object.new.tap { |s| s.define_singleton_method(:scan) { |_| :maybe } }
    assert_equal 'unexpected scanner result: :maybe', check('hi', scanner: odd).detail
    infected = Object.new.tap { |s| s.define_singleton_method(:scan) { |_| [:infected, 'Sig'] } }
    assert_equal :malware_detected, check('hi', scanner: infected).reason
  end

  def command(script, **) = UploadInspector::Scanners::Command.new('sh', '-c', script, 'sh', **)

  def test_command_adapter_by_exit_status
    grep = command('grep -q EICAR "$1" && { echo "$1: Eicar-Sig FOUND"; exit 1; }; exit 0')
    assert check('hello', scanner: grep).safe?
    result = check(EICAR, scanner: grep)
    assert_equal [:malware_detected, 'Eicar-Sig'], [result.reason, result.detail]
    assert_equal 'Scanners::Error: sh exited with 2: boom',
                 check('hi', scanner: command('echo boom; exit 2')).detail.delete_prefix('UploadInspector::')
  end

  def test_command_adapter_timeout_and_missing_binary
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    assert_match(/timed out/, check('hi', scanner: command('sleep 5', timeout: 0.2)).detail)
    assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 2
    missing = UploadInspector::Scanners::Command.new('no-such-scanner-binary')
    assert_match(/ENOENT/, check('hi', scanner: missing).detail)
  end

  def test_scans_after_the_sandboxed_check
    result = UploadInspector.check(write_file('n.txt', EICAR), filename: 'n.txt', allowed_types: %w[text/plain],
                                                               scanner: clamav)
    assert_equal :malware_detected, result.reason
  end

  # Against a real clamd (CI's clamav/clamav service): CLAMD_HOST=localhost.
  def test_real_clamd
    skip 'set CLAMD_HOST to scan with a real clamd' unless ENV['CLAMD_HOST']
    real = UploadInspector::Scanners::ClamAV.new(host: ENV['CLAMD_HOST'], port: Integer(ENV.fetch('CLAMD_PORT', 3310)))
    assert_equal :malware_detected, check(EICAR, scanner: real).reason
    assert check(clean_pdf, filename: 'x.pdf', scanner: real).safe?
  end

  def test_sanitize_scans_the_cleaned_copy
    to = tmp_path('clean.txt')
    result = UploadInspector.sanitize(write_file('s.txt', EICAR), filename: 's.txt', to:, sandbox: false,
                                                                  allowed_types: %w[text/plain], scanner: clamav)
    assert_equal :malware_detected, result.reason
    refute File.exist?(to)
    assert UploadInspector.sanitize(write_file('c.txt', 'hello'), filename: 'c.txt', to:, sandbox: false,
                                                                  allowed_types: %w[text/plain], scanner: clamav).safe?
    assert_equal ['hello'], @clamd.streams.last(1)
  end

  def test_no_scanner_behaves_as_before
    assert check(EICAR).safe?
  end
end
