# frozen_string_literal: true

require 'json'
require 'optparse'
require_relative '../upload_inspector'

module UploadInspector
  # Command line: check files, re-scan a directory of stored uploads, or sanitize a file.
  #
  #   upload_inspector check FILE... [options]
  #   upload_inspector scan DIR [--recursive] [options]
  #   upload_inspector sanitize FILE --out PATH [options]
  #
  # Exit status: 0 every file safe, 1 at least one unsafe, 2 usage or runtime error.
  # The file name checked against the content is the file's basename.
  class CLI
    USAGE = <<~TEXT
      Usage: upload_inspector check FILE... [options]
             upload_inspector scan DIR [--recursive] [options]
             upload_inspector sanitize FILE --out PATH [options]
    TEXT
    PRESETS = %w[PDF OFFICE DOCUMENTS IMAGES SVG MEDIA TEXT].freeze

    def self.start(argv = ARGV, out: $stdout, err: $stderr) = new(out:, err:).run(argv)

    def initialize(out:, err:)
      @out = out
      @err = err
      @options = {}
      @check = {}
    end

    # Returns the exit status.
    def run(argv)
      command, *args = argv
      args = parser(command).parse(args)
      case command
      when 'check' then report(args.map { |path| [path, check(path)] }, usage_if: args.empty?)
      when 'scan' then scan(args)
      when 'sanitize' then sanitize(args)
      else usage_error(command ? "unknown command: #{command}" : nil)
      end
    rescue OptionParser::ParseError, ArgumentError, SystemCallError => e
      @err.puts("upload_inspector: #{e.message}")
      2
    end

  private

    def parser(command)
      OptionParser.new do |opts|
        opts.banner = USAGE
        opts.on('--types LIST', Array, "Allowed types: MIME types or presets (#{PRESETS.join(', ').downcase})") do |list|
          @check[:allowed_types] = list.flat_map { |item| preset_or_type(item) }
        end
        opts.on('--json', 'One JSON object per file, one per line') { @options[:json] = true }
        opts.on('--no-sandbox', 'Inspect in this process') { @check[:sandbox] = false }
        opts.on('--clamav SOCKET', 'Also scan with clamd: a Unix socket path or HOST:PORT') do |target|
          @check[:scanner] = clamav(target)
        end
        opts.on('--recursive', '-r', 'scan: descend into subdirectories') { @options[:recursive] = true } if command == 'scan'
        opts.on('--out PATH', 'sanitize: where to write the cleaned file') { @options[:out] = _1 } if command == 'sanitize'
      end
    end

    def preset_or_type(item)
      name = item.upcase
      return Presets.const_get(name) if PRESETS.include?(name)
      raise ArgumentError, "unknown type or preset: #{item}" unless item.include?('/')

      item
    end

    def clamav(target)
      host, port = target.split(':', 2)
      return Scanners::ClamAV.new(socket: target) if target.start_with?('/') || port.nil?

      Scanners::ClamAV.new(host:, port: Integer(port))
    end

    def check(path, **) = UploadInspector.check(path, filename: File.basename(path), **@check, **)

    def scan(args)
      return usage_error('scan takes one directory') unless args.size == 1 && File.directory?(args.first)

      pattern = @options[:recursive] ? '**/*' : '*'
      paths = Dir.glob(pattern, File::FNM_DOTMATCH, base: args.first).sort.filter_map do |relative|
        path = File.join(args.first, relative)
        path if File.file?(path) && !File.symlink?(path) # a link may point outside the store
      end
      report(paths.lazy.map { |path| [path, check(path)] })
    end

    def sanitize(args)
      return usage_error('sanitize takes one FILE and --out PATH') unless args.size == 1 && @options[:out]

      path = args.first
      result = UploadInspector.sanitize(path, to: @options[:out], filename: File.basename(path), **@check)
      report([[path, result]])
    end

    # Prints each result as it comes (a large scan shows progress) and returns the exit status.
    def report(results, usage_if: false)
      return usage_error('no files given') if usage_if

      unsafe = false
      results.each do |path, result|
        unsafe ||= !result.safe?
        @out.puts(@options[:json] ? JSON.generate(row(path, result)) : line(path, result))
      end
      unsafe ? 1 : 0
    end

    def row(path, result)
      { path:, safe: result.safe?, reason: result.reason, detail: result.detail, detected_type: result.detected_type,
        sanitized_path: result.sanitized_path, }.compact
    end

    def line(path, result)
      return "SAFE    #{path} (#{result.detected_type})" if result.safe?

      "UNSAFE  #{path}: #{[result.reason, result.detail].compact.join(': ')}"
    end

    def usage_error(message)
      @err.puts("upload_inspector: #{message}") if message
      @err.puts(USAGE)
      2
    end
  end
end
