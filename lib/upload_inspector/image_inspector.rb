# frozen_string_literal: true

module UploadInspector
  # Structural check of PNG, JPEG, GIF and WebP files. Nothing is decoded.
  #
  # The container is walked block by block: every length must stay inside the file, the
  # declared dimensions must be within max_image_pixels (decompression bombs for whatever
  # resizes the image later), and the file must end where the image ends, so nothing can be
  # appended (a script, an archive: the usual image polyglot). JPEG files holding several
  # images back to back (Multi-Picture Format: HDR gain maps, depth maps) are accepted.
  class ImageInspector
    include Rejectable

    FORMATS = { 'image/png' => :png, 'image/jpeg' => :jpeg, 'image/gif' => :gif, 'image/webp' => :webp }.freeze
    PNG_SIGNATURE = "\x89PNG\r\n\x1A\n".b
    JPEG_SOI = "\xFF\xD8".b
    JPEG_STANDALONE = [0x01, *0xD0..0xD8].freeze # markers without a length field
    JPEG_FRAME = ([*0xC0..0xCF] - [0xC4, 0xC8, 0xCC]).freeze # SOFn carry the dimensions
    JPEG_NEXT_MARKER = /\xFF[^\x00\xD0-\xD7\xFF]/n # skips stuffed bytes and restart markers
    SCAN_CHUNK_SIZE = MEGABYTE

    def initialize(policy)
      @policy = policy
    end

    def verify!(path, type)
      File.open(path, 'rb') do |io|
        @io = io
        @size = io.size
        send(FORMATS.fetch(type))
        reject!(:image_trailing_data, "#{@size - io.pos} bytes after the image") unless io.pos == @size
      end
    end

  private

    attr_reader :policy

    def png
      malformed!('signature') unless take(8) == PNG_SIGNATURE
      length, type = take(8).unpack('Na4')
      malformed!('IHDR must come first') unless type == 'IHDR' && length == 13
      check_pixels!(*take(8).unpack('NN'))
      skip(5 + 4)

      has_data = false
      until type == 'IEND'
        length, type = take(8).unpack('Na4')
        malformed!('chunk type') unless type.match?(/\A[A-Za-z]{4}\z/)
        has_data ||= type == 'IDAT'
        skip(length + 4) # data and CRC
      end
      malformed!('no image data') unless has_data
    end

    def jpeg
      loop do
        jpeg_image
        break unless peek(2) == JPEG_SOI
      end
    end

    def jpeg_image
      malformed!('signature') unless take(2) == JPEG_SOI
      frames = 0
      loop do
        marker = jpeg_marker
        break if marker == 0xD9
        next if JPEG_STANDALONE.include?(marker)

        length = take(2).unpack1('n')
        malformed!('segment length') if length < 2
        if JPEG_FRAME.include?(marker)
          malformed!('frame header') if length < 7
          _, height, width = take(5).unpack('Cnn')
          check_pixels!(width, height)
          frames += 1
          skip(length - 7)
        else
          skip(length - 2)
        end
        skip_jpeg_scan_data if marker == 0xDA
      end
      malformed!('no frame') if frames.zero?
    end

    def jpeg_marker
      malformed!('marker') unless take(1) == "\xFF".b
      marker = take(1).ord
      marker = take(1).ord while marker == 0xFF # fill bytes
      malformed!('marker') if marker.zero?
      marker
    end

    # Entropy-coded data has no length; it runs until the next real marker.
    def skip_jpeg_scan_data
      loop do
        start = @io.pos
        chunk = @io.read(SCAN_CHUNK_SIZE) || malformed!('truncated')
        index = chunk.index(JPEG_NEXT_MARKER)
        return @io.seek(start + index) if index

        malformed!('truncated') if @io.pos >= @size
        @io.seek(-1, IO::SEEK_CUR) if chunk.getbyte(-1) == 0xFF # marker split across chunks
      end
    end

    def gif
      malformed!('signature') unless %w[GIF87a GIF89a].include?(take(6))
      width, height, flags = take(7).unpack('vvC')
      check_pixels!(width, height)
      skip_gif_color_table(flags)

      images = 0
      loop do
        case take(1).ord
        when 0x3B then break
        when 0x21 # extension: label, then data sub-blocks
          take(1)
          skip_gif_sub_blocks
        when 0x2C
          _, _, width, height, flags = take(9).unpack('vvvvC')
          check_pixels!(width, height)
          skip_gif_color_table(flags)
          take(1) # LZW minimum code size
          skip_gif_sub_blocks
          images += 1
        else malformed!('block')
        end
      end
      malformed!('no image data') if images.zero?
    end

    def skip_gif_color_table(flags)
      skip(3 * (2 << (flags & 7))) if flags.anybits?(0x80)
    end

    def skip_gif_sub_blocks
      while (length = take(1).ord).positive?
        skip(length)
      end
    end

    def webp
      riff, riff_size, format = take(12).unpack('a4Va4')
      malformed!('signature') unless riff == 'RIFF' && format == 'WEBP'
      reject!(:image_trailing_data, 'data after the RIFF container') if riff_size + 8 < @size
      malformed!('truncated') if riff_size + 8 > @size

      first = true
      while @io.pos < @size
        fourcc, length = take(8).unpack('a4V')
        header = first ? take([length, 10].min) : ''.b
        check_pixels!(*webp_dimensions(fourcc, header)) if first
        skip(length - header.bytesize)
        skip(1) if length.odd? && @io.pos < @size # chunks are padded to an even size
        first = false
      end
      malformed!('no image data') if first
    end

    def webp_dimensions(fourcc, header)
      case fourcc
      when 'VP8X' # canvas size, 24-bit little endian, stored minus one
        malformed!('VP8X header') if header.bytesize < 10
        [header.byteslice(4, 3), header.byteslice(7, 3)].map { |bytes| "#{bytes}\0".b.unpack1('V') + 1 }
      when 'VP8L'
        malformed!('VP8L header') if header.bytesize < 5 || header.getbyte(0) != 0x2F
        bits = header.byteslice(1, 4).unpack1('V')
        [(bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1]
      when 'VP8 '
        malformed!('VP8 header') if header.bytesize < 10 || header.byteslice(3, 3) != "\x9D\x01\x2A".b
        header.byteslice(6, 4).unpack('vv').map { |value| value & 0x3FFF }
      else malformed!('first chunk')
      end
    end

    def check_pixels!(width, height)
      malformed!('zero dimension') if width.zero? || height.zero?
      return if width * height <= policy.max_image_pixels

      reject!(:image_too_many_pixels, "#{width}x#{height} exceeds #{policy.max_image_pixels} pixels")
    end

    def take(length)
      data = @io.read(length)
      data && data.bytesize == length ? data : malformed!('truncated')
    end

    def peek(length)
      data = @io.read(length)
      @io.seek(-data.bytesize, IO::SEEK_CUR) if data
      data
    end

    def skip(length)
      malformed!('truncated') if length.negative? || @io.pos + length > @size
      @io.seek(length, IO::SEEK_CUR)
    end

    def malformed!(what)
      reject!(:image_malformed, what)
    end
  end
end
