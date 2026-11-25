# frozen_string_literal: true

module UploadInspector
  module Sanitizers
    # Structural check of an embedded ICC color profile (ICC.1 header and tag table), so the
    # image rewriter keeps a real profile, not an arbitrary blob stored where one belongs.
    # Tag data is not interpreted: only reencode replaces the profile entirely.
    module IccProfile
      HEADER_SIZE = 128
      SIGNATURE = 'acsp'.b
      MAX_SIZE = MEGABYTE # larger profiles are dropped

      module_function

      # True when +data+ is a profile whose declared size is its length and whose tags lie inside it.
      def valid?(data)
        return false unless data && data.bytesize >= HEADER_SIZE + 4 && data.bytesize <= MAX_SIZE
        return false unless data.byteslice(0, 4).unpack1('N') == data.bytesize && data.byteslice(36, 4) == SIGNATURE

        count = data.byteslice(HEADER_SIZE, 4).unpack1('N')
        return false if HEADER_SIZE + 4 + (count * 12) > data.bytesize

        count.times.all? do |index|
          offset, length = data.byteslice(HEADER_SIZE + 4 + (index * 12) + 4, 8).unpack('NN')
          offset >= HEADER_SIZE && offset + length <= data.bytesize
        end
      end

      # The profile of a PNG iCCP chunk payload (name, NUL, method 0, zlib data), nil when it
      # cannot be read within MAX_SIZE.
      def from_png(payload)
        name_end = payload.index("\0".b)
        return unless name_end && name_end.between?(1, 79) && payload.getbyte(name_end + 1).zero?

        inflater = Zlib::Inflate.new
        profile = +''.b
        inflater.inflate(payload.byteslice((name_end + 2)..)) do |chunk|
          profile << chunk
          return nil if profile.bytesize > MAX_SIZE
        end
        inflater.finished? ? profile : nil
      rescue Zlib::Error
        nil
      ensure
        inflater&.close
      end
    end
  end
end
