# frozen_string_literal: true

module UploadInspector
  module Sanitizers
    # Rewrites a HEIC / HEIF / AVIF image or MP4 / QuickTime video that passed the check, keeping
    # the top-level boxes needed to play it. Any other top-level box (free, skip, uuid such as
    # XMP, unknown) is removed when nothing follows it, and otherwise overwritten in place with
    # a zero-filled `free` box of the same size: sample tables (stco/co64), item locations
    # (iloc) and fragment indexes (tfra, sidx) hold absolute offsets, which moving any byte
    # would break. Boxes nested inside moov or meta are copied unchanged.
    class IsoBmffRewriter
      KEPT = %w[ftyp moov mdat meta moof mfra sidx ssix styp prft].freeze
      ZEROS = ("\0" * MEGABYTE).b.freeze

      def initialize(policy)
        @policy = policy
      end

      # Writes the rewritten file of +path+ (detected +type+) to +output+.
      def rewrite(path, type, output)
        boxes = []
        IsoBmffInspector.new(@policy).verify!(path, type) { |*box| boxes << box }
        last_kept = boxes.rindex { |box, *| KEPT.include?(box) }
        File.open(path, 'rb') do |io|
          File.open(output, 'wb') do |out|
            boxes.each_with_index do |(box, offset, length, header), index|
              if KEPT.include?(box) then IO.copy_stream(io, out, length, offset)
              elsif index < last_kept then write_free(out, length, header)
              end
            end
          end
        end
      end

    private

      # Same total size and header form (32- or 64-bit size) as the box it replaces.
      def write_free(out, length, header)
        out.write(header == 16 ? [1, 'free', length].pack('Na4Q>') : [length, 'free'].pack('Na4'))
        remaining = length - header
        while remaining.positive?
          remaining -= out.write(ZEROS.byteslice(0, [remaining, ZEROS.bytesize].min))
        end
      end
    end
  end
end
