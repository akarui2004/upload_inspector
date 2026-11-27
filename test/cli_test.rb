# frozen_string_literal: true

require 'test_helper'
require 'stringio'
require 'upload_inspector/cli'

# Command line, run in this process (exit status returned, output captured).
class CLITest < Minitest::Test
  include FixtureBuilder

  def run_cli(*argv)
    out = StringIO.new
    err = StringIO.new
    status = UploadInspector::CLI.start(argv, out:, err:)
    [status, out.string, err.string]
  end

  def store
    write_file('a.txt', "hello\n")
    write_file('b.csv', '<script>x</script>')
    FileUtils.mkdir_p(tmp_path('sub'))
    write_file('sub/c.pdf', clean_pdf)
    File.symlink('/etc/passwd', tmp_path('link.txt'))
    tmp_path('')
  end

  def test_check_exit_status_and_text_output
    status, out, = run_cli('check', write_file('a.txt', 'hi'), '--types', 'text', '--no-sandbox')
    assert_equal 0, status
    assert_match(/\ASAFE    .*a\.txt \(text\/plain\)\n\z/, out)
    status, out, = run_cli('check', write_file('x.txt', clean_pdf), '--no-sandbox')
    assert_equal 1, status
    assert_match(/UNSAFE  .*x\.txt: extension_mismatch/, out)
  end

  def test_scan_lists_unsafe_files_as_json_lines
    dir = store
    status, out, = run_cli('scan', dir, '--json', '--types', 'text,pdf', '--no-sandbox')
    assert_equal 1, status
    rows = out.lines.map { JSON.parse(_1) }
    assert_equal %w[a.txt b.csv], rows.map { File.basename(_1['path']) } # no subdirectory, no symlink
    assert_equal [true, 'text_markup'], [rows[0]['safe'], rows[1]['reason']]

    _, out, = run_cli('scan', dir, '-r', '--json', '--types', 'text,application/pdf', '--no-sandbox')
    assert_equal %w[a.txt b.csv c.pdf], out.lines.map { File.basename(JSON.parse(_1)['path']) }
  end

  def test_sanitize_writes_the_clean_copy
    to = tmp_path('clean.txt')
    status, out, = run_cli('sanitize', write_file('in.txt', 'hi'), '--out', to, '--types', 'text', '--json')
    assert_equal 0, status
    assert_equal to, JSON.parse(out)['sanitized_path']
    assert_equal 'hi', File.read(to)
  end

  def test_errors_exit_2
    assert_equal 2, run_cli('nope').first
    assert_equal 2, run_cli('check').first
    assert_equal 2, run_cli('scan', tmp_path('missing')).first
    assert_equal 2, run_cli('sanitize', write_file('a.txt', 'x')).first
    status, _, err = run_cli('check', 'a.txt', '--types', 'bogus')
    assert_equal [2, "upload_inspector: unknown type or preset: bogus\n"], [status, err]
    assert_equal 2, run_cli('check', tmp_path('missing.txt'), '--no-sandbox').first
  end

  def test_clamav_option
    clamd = TCPServer.new('127.0.0.1', 0)
    server = Thread.new do
      client = clamd.accept
      client.read(14) # zINSTREAM\0 + one chunk header
      client.write("stream: Eicar FOUND\0")
      client.close
    end
    file = write_file('a.txt', 'hi')
    status, out, = run_cli('check', file, '--types', 'text', '--no-sandbox', '--clamav', "127.0.0.1:#{clamd.addr[1]}")
    assert_equal [1, "UNSAFE  #{file}: malware_detected: Eicar\n"], [status, out]

    _, out, = run_cli('check', file, '--types', 'text', '--no-sandbox', '--clamav', tmp_path('no.sock'))
    assert_match(/scanner_failed: .*ENOENT/, out) # a path is a Unix socket
  ensure
    server&.join(1)
    clamd&.close
  end
end
