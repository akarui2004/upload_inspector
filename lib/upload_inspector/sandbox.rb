# frozen_string_literal: true

require 'io/wait'
require 'rbconfig'

module UploadInspector
  # Runs the inspection in a separate Ruby process with CPU, memory and wall-clock limits.
  # A crash, hang or memory blow-up kills only the child and is reported as a rejection,
  # so the host process (web server / job worker) is never affected.
  #
  # This is resource isolation, not a security boundary: the child runs as the same user.
  # Parsing is pure Ruby and never executes file content, which keeps that risk low.
  module Sandbox
    LIB_DIR = File.expand_path('..', __dir__)
    CHILD_SCRIPT = "require 'upload_inspector'; UploadInspector::Sandbox.child_main(ARGV.fetch(0))"
    READ_CHUNK_SIZE = 16 * 1024
    MEMORY_LIMIT_SUPPORTED = RUBY_PLATFORM.include?('linux')

    module_function

    def run(path, filename:, policy:)
      reader, writer = IO.pipe
      payload = JSON.generate(path: File.expand_path(path), filename: filename.to_s, policy: policy.to_h)
      pid = Process.spawn(RbConfig.ruby, '-I', LIB_DIR, '-e', CHILD_SCRIPT, payload,
                          spawn_options(policy, writer))
      writer.close
      collect(pid, reader, policy.timeout)
    rescue SystemCallError => e
      Result.reject(:sandbox_failed, e.message)
    ensure
      writer&.close unless writer&.closed?
      reader&.close unless reader&.closed?
    end

    # Entry point inside the child process.
    def child_main(payload)
      input = JSON.parse(payload, symbolize_names: true)
      policy = Policy.new(**input.fetch(:policy))
      result = Inspector.new(policy).call(input.fetch(:path), filename: input.fetch(:filename))
      $stdout.write(JSON.generate(result.to_h))
    rescue NoMemoryError
      $stdout.write(JSON.generate(Result.reject(:resource_limit, 'memory limit').to_h))
    end

    def spawn_options(policy, writer)
      options = { out: writer, err: File::NULL, in: File::NULL, pgroup: true, chdir: Dir.tmpdir }
      # RLIMIT_DATA is enforced on Linux (production containers); macOS rejects lowering it.
      options[:rlimit_data] = policy.memory_limit if policy.memory_limit && MEMORY_LIMIT_SUPPORTED
      options[:rlimit_cpu] = policy.cpu_limit if policy.cpu_limit
      options
    end

    def collect(pid, reader, timeout)
      output = read_until_eof(reader, timeout)
      if output.nil?
        kill(pid)
        return Result.reject(:timeout, "exceeded #{timeout}s")
      end

      _, status = Process.wait2(pid)
      return Result.reject(:resource_limit, "child killed by signal #{status.termsig}") if status.signaled?
      return Result.reject(:inspection_failed, "child exited with status #{status.exitstatus}") unless status.success?

      parse(output)
    end

    # Returns nil when the deadline passes before the child closes its output.
    def read_until_eof(reader, timeout)
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
      output = +''
      loop do
        remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
        return nil if remaining <= 0
        next unless reader.wait_readable(remaining)

        chunk = reader.read_nonblock(READ_CHUNK_SIZE, exception: false)
        return output if chunk.nil?

        output << chunk unless chunk == :wait_readable
      end
    end

    def kill(pid)
      Process.kill(:KILL, -pid)
    rescue Errno::ESRCH
      nil
    ensure
      Process.wait(pid) rescue Errno::ECHILD # rubocop:disable Style/RescueModifier
    end

    def parse(output)
      data = JSON.parse(output, symbolize_names: true)
      Result.new(safe: data.fetch(:safe) == true, reason: data[:reason]&.to_sym,
                 detail: data[:detail], detected_type: data[:detected_type])
    rescue JSON::ParserError, KeyError
      Result.reject(:inspection_failed, 'unreadable sandbox output')
    end
  end
end
