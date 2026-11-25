# frozen_string_literal: true

module UploadInspector
  module Sanitizers
    # Rewrites a PNG, JPEG, GIF or WebP that passed the check, keeping only the blocks needed to
    # display it. Metadata (EXIF with GPS, XMP), comments, unknown chunks and extra MPF images are
    # dropped, and with them whatever a payload hid there (e.g. <?php in a JPEG comment).
    # Kept blocks are copied byte for byte; pixel data is not decoded (reencode covers that).
    class ImageRewriter
      PNG_KEPT = [:signature, *%w[IHDR PLTE IDAT IEND tRNS gAMA cHRM sRGB iCCP pHYs acTL fcTL fdAT]].freeze # acTL.. = APNG frames
      PNG_MAX_CHUNK = 0x7FFF_FFFF
      # Frames, Huffman/arithmetic/quantization tables, DNL, restart interval, hierarchical
      # DHP/EXP, scans and restart markers. APP segments are decided one by one below.
      JPEG_KEPT = [*ImageInspector::JPEG_FRAME, 0xC4, 0xCC, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xDA, :scan_data, *0xD0..0xD7].freeze
      JPEG_JFIF = "JFIF\0".b
      JPEG_EXIF = "Exif\0\0".b
      JPEG_ICC = "ICC_PROFILE\0".b
      JPEG_ADOBE = 'Adobe'.b # APP14: color transform of CMYK/YCCK images; fixed 12-byte payload
      JPEG_ORIENTATION_TAG = 0x0112
      GIF_LOOP = /\A\x0B(?:NETSCAPE2\.0|ANIMEXTS1\.0)\z/n
      WEBP_KEPT = ['VP8 ', 'VP8L', 'VP8X', 'ALPH', 'ANIM', 'ANMF', 'ICCP'].freeze
      WEBP_ICC_FLAG = 0x20
      WEBP_METADATA_FLAGS = 0x0C # EXIF and XMP
      MAX_ICC_SIZE = MEGABYTE # larger color profiles are dropped, not copied

      def initialize(policy, keep_orientation: false)
        @policy = policy
        @keep_orientation = keep_orientation
      end

      # Writes the rewritten image of +path+ (detected +type+) to +output+.
      def rewrite(path, type, output)
        blocks = []
        ImageInspector.new(@policy).verify!(path, type) { |*block| blocks << block }
        File.open(path, 'rb') do |io|
          @io = io
          pieces = send(ImageInspector::FORMATS.fetch(type), blocks)
          File.open(output, 'wb') do |out|
            # A piece is either new bytes or an [offset, length] range of the source.
            pieces.each { |piece| piece.is_a?(String) ? out.write(piece) : IO.copy_stream(io, out, piece[1], piece[0]) }
          end
        end
      end

    private

      def png(blocks)
        idat = blocks.select { |kind, *| kind == 'IDAT' } # consecutive, as the PNG spec requires
        blocks.each_with_object([]) do |(kind, offset, length), pieces|
          next unless PNG_KEPT.include?(kind)
          next if kind == 'iCCP' && length > MAX_ICC_SIZE
          next pieces << [offset, length] unless kind == 'IDAT'

          pieces.concat(merged_idat(idat)) if offset == idat.first[1]
        end
      end

      # One IDAT holding the data of all of them (with a fresh CRC), unless that would overflow.
      def merged_idat(chunks)
        ranges = chunks.map { |_, offset, length| [offset + 8, length - 12] }
        size = ranges.sum(&:last)
        return chunks.map { |_, offset, length| [offset, length] } if size > PNG_MAX_CHUNK

        crc = Zlib.crc32('IDAT')
        ranges.each { |offset, length| each_slice(offset, length) { |data| crc = Zlib.crc32(data, crc) } }
        ["#{[size].pack('N')}IDAT".b, *ranges, [crc].pack('N')]
      end

      def jpeg(blocks)
        pieces = []
        icc_size = 0
        orientation = nil
        exif_at = 1 # minimal EXIF goes right after SOI, or after a JFIF APP0 that follows it
        blocks.each do |kind, offset, length|
          case kind
          when 0xD8 then pieces << [offset, length]
          when 0xD9 then break pieces << [offset, length] # MPF: keep the primary image only
          when 0xE0
            next unless read(offset, length).byteslice(4, 5) == JPEG_JFIF

            exif_at = 2 if pieces.size == 1
            pieces << [offset, length]
          when 0xE1 then orientation ||= exif_orientation(read(offset, length)) if @keep_orientation
          when 0xE2
            next unless read(offset, length).byteslice(4, 12) == JPEG_ICC && (icc_size += length) <= MAX_ICC_SIZE

            pieces << [offset, length]
          when 0xEE then pieces << [offset, length] if length == 16 && read(offset, length).byteslice(4, 5) == JPEG_ADOBE
          else pieces << [offset, length] if JPEG_KEPT.include?(kind)
          end
        end
        pieces.insert(exif_at, orientation_segment(orientation)) if orientation
        pieces
      end

      # Orientation (1..8) from the first IFD of an APP1 EXIF segment, nil when absent or unreadable.
      def exif_orientation(segment)
        return unless segment.byteslice(4, 6) == JPEG_EXIF

        tiff = segment.byteslice(10..)
        short, long = { 'II' => %w[v V], 'MM' => %w[n N] }[tiff.byteslice(0, 2)]
        return unless short && tiff.bytesize >= 8

        ifd = tiff.byteslice(4, 4).unpack1(long)
        count = tiff.byteslice(ifd, 2)&.unpack1(short).to_i
        count.times do |index|
          entry = tiff.byteslice(ifd + 2 + (index * 12), 12)
          return unless entry&.bytesize == 12

          tag, type, number = entry.unpack("#{short}#{short}#{long}")
          next unless tag == JPEG_ORIENTATION_TAG

          value = entry.byteslice(8, 2).unpack1(short)
          return type == 3 && number == 1 && (1..8).cover?(value) ? value : nil
        end
        nil
      end

      # APP1 EXIF holding only the Orientation tag: big-endian TIFF, one IFD with one SHORT entry.
      def orientation_segment(orientation)
        tiff = "MM\0*".b + [8, 1, JPEG_ORIENTATION_TAG, 3, 1, orientation, 0, 0].pack('NnnnNnnN')
        payload = JPEG_EXIF + tiff
        "\xFF\xE1".b + [payload.bytesize + 2].pack('n') + payload
      end

      def gif(blocks)
        blocks.filter_map do |kind, offset, length|
          [offset, length] if kind != :extension || gif_extension_kept?(offset, length)
        end
      end

      # Graphic control (frame delay, transparency) and the animation loop count; both have a
      # fixed size, so no sub-block can carry extra data.
      def gif_extension_kept?(offset, length)
        head = read(offset, [length, 14].min)
        case head.getbyte(1)
        when 0xF9 then length == 8
        when 0xFF then length == 19 && head.byteslice(2, 12).match?(GIF_LOOP)
        else false
        end
      end

      def webp(blocks)
        chunks = blocks.filter_map do |fourcc, offset, _|
          next unless WEBP_KEPT.include?(fourcc)

          declared = read(offset + 4, 4).unpack1('V')
          [fourcc, offset, declared] unless fourcc == 'ICCP' && declared > MAX_ICC_SIZE
        end
        icc = chunks.any? { |fourcc, *| fourcc == 'ICCP' }
        body = chunks.flat_map do |fourcc, offset, declared|
          chunk = fourcc == 'VP8X' ? vp8x(read(offset, 8 + declared), icc) : [offset, 8 + declared]
          declared.odd? ? [chunk, "\0".b] : [chunk] # chunks are padded to an even size
        end
        size = body.sum { |piece| piece.is_a?(String) ? piece.bytesize : piece[1] }
        ["RIFF#{[size + 4].pack('V')}WEBP".b, *body]
      end

      # The feature flags must match the chunks left: no EXIF/XMP, ICC only if kept.
      def vp8x(chunk, icc)
        flags = chunk.getbyte(8) & ~WEBP_METADATA_FLAGS
        chunk.setbyte(8, icc ? flags | WEBP_ICC_FLAG : flags & ~WEBP_ICC_FLAG)
        chunk
      end


      def read(offset, length)
        @io.seek(offset)
        @io.read(length).to_s
      end

      def each_slice(offset, length)
        @io.seek(offset)
        while length.positive?
          data = @io.read([length, MEGABYTE].min)
          yield data
          length -= data.bytesize
        end
      end
    end
  end
end
