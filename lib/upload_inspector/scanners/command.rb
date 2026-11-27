# frozen_string_literal: true

module UploadInspector
  module Scanners
    # Runs a scanner command on the file, judged by its exit status: 0 clean, 1 infected,
    # anything else (or no exit within +timeout+ seconds) an Error. The absolute file path is
    # appended as the last argument; no shell is involved.
    #
    #   UploadInspector::Scanners::Command.new('clamdscan', '--no-summary', '--fdpass')
    #
    # The signature is taken from a "<path>: <signature> FOUND" line (ClamAV style), else from
    # the first output line.
    class Command
      def initialize(*command, timeout: 60)
        raise ArgumentError, 'command is required' if command.empty?

        @command = command.map(&:to_s)
        @timeout = timeout
      end

      def scan(path)
        status, output = run(File.expand_path(path)) # absolute: never read as an option
        case status.exitstatus
        when 0 then :clean
        when 1 then [:infected, signature(output)]
        else raise Error, "#{@command.first} exited with #{status.exitstatus || status}: #{output.strip[0, 200]}"
        end
      end

      private

      def run(path)
        reader, writer = IO.pipe
        pid = Process.spawn(*@command, path, in: File::NULL, out: writer, err: writer, pgroup: true)
        writer.close
        output = Thread.new { reader.read }
        output.report_on_exception = false # reader is closed under it after a timeout
        unless output.join(@timeout)
          begin
            Process.kill(:KILL, -pid) # the whole process group, helpers included
          rescue Errno::ESRCH
            nil # exited just now
          end
          Process.wait(pid)
          raise Error, "#{@command.first} timed out after #{@timeout}s"
        end
        [Process.wait2(pid).last, output.value]
      ensure
        writer&.close unless writer&.closed?
        reader&.close
      end

      def signature(output)
        output[/: (.+) FOUND$/, 1] || output.lines.first.to_s.strip[0, 200]
      end
    end
  end
end
