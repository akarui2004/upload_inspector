# frozen_string_literal: true

require 'socket'

module UploadInspector
  module Scanners
    # Scans with clamd over its socket (INSTREAM), no clamdscan binary or gem needed.
    #
    #   UploadInspector::Scanners::ClamAV.new                                  # local Unix socket
    #   UploadInspector::Scanners::ClamAV.new(host: 'clamav', port: 3310, timeout: 60)
    #
    # +timeout+ bounds the connect and each socket read/write, so the wait for clamd's verdict too.
    # +max_stream+ must not exceed clamd's StreamMaxLength (default 25 MB there): bigger files
    # raise Error (so :scanner_failed) instead of being cut off by clamd.
    class ClamAV
      DEFAULT_SOCKET = '/var/run/clamav/clamd.ctl'
      CHUNK_SIZE = 64 * 1024
      MAX_REPLY = 4096

      def initialize(socket: nil, host: nil, port: 3310, timeout: 30, max_stream: 25 * 1024 * 1024)
        raise ArgumentError, 'pass socket: or host:, not both' if socket && host

        @socket = socket || (DEFAULT_SOCKET unless host)
        @host = host
        @port = port
        @timeout = timeout
        @max_stream = max_stream
      end

      def scan(path)
        size = File.size(path)
        raise Error, "#{size} bytes exceeds max_stream (#{@max_stream})" if size > @max_stream

        reply = connect { |sock| stream(sock, path) }
        case reply
        when 'stream: OK' then :clean
        when /\Astream: (.+) FOUND\z/ then [:infected, Regexp.last_match(1)]
        else raise Error, "clamd: #{reply[0, 200]}"
        end
      end

      private

      def connect
        sock = @host ? Socket.tcp(@host, @port, connect_timeout: @timeout) : UNIXSocket.new(@socket)
        sock.timeout = @timeout
        yield sock
      ensure
        sock&.close
      end

      # zINSTREAM: chunks of [length uint32 big-endian][bytes], a zero length ends the stream;
      # the reply is NUL-terminated.
      def stream(sock, path)
        sock.write("zINSTREAM\0")
        File.open(path, 'rb') do |file|
          while (chunk = file.read(CHUNK_SIZE))
            sock.write([chunk.bytesize].pack('N'), chunk)
          end
        end
        sock.write([0].pack('N'))
        reply = sock.gets("\0", MAX_REPLY) or raise Error, 'clamd closed the connection without a reply'
        reply.chomp("\0").strip
      end
    end
  end
end
