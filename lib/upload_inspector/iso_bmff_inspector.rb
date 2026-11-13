# frozen_string_literal: true

module UploadInspector
  # Structural check of ISO base media files: HEIC / HEIF / AVIF images and MP4 / QuickTime
  # video. Nothing is decoded: box headers are read and their payloads skipped.
  #
  # - every box length must stay inside its parent, and the top-level boxes must cover the
  #   file exactly, so nothing can be appended (a script, an archive: the usual polyglot)
  # - the file must start with an `ftyp` box whose brands belong to the detected type
  #   (Marcel reports any unknown `ftyp` file as video/quicktime)
  # - images must carry a `meta` box, video a `moov` box
  # - declared dimensions (`ispe` image properties, `tkhd` track headers) must be within
  #   max_image_pixels
  class IsoBmffInspector
    include Rejectable

    # Accepted major or compatible brands per detected type.
    BRANDS = {
      'image/heic' => %w[heic heix heim heis],
      'image/heif' => %w[mif1 msf1],
      'image/avif' => %w[avif avis],
      'video/mp4' => %w[isom iso2 iso3 iso4 iso5 iso6 mp41 mp42 avc1 mp71],
      'video/quicktime' => ['qt  '],
    }.freeze
    TYPES = BRANDS.keys.freeze
    BOX_TYPE = /\A[\x20-\x7E]{4}\z/n

    def initialize(policy)
      @policy = policy
    end

    def verify!(path, type)
      File.open(path, 'rb') do |io|
        @io = io
        image = type.start_with?('image/')
        top = {}
        each_box(0, io.size) do |box, start, finish|
          if top.empty?
            malformed!('ftyp must come first') unless box == 'ftyp'
            check_ftyp!(type, start, finish)
          end
          top[box] = true
          image_properties(start + 4, finish) if image && box == 'meta' # FullBox: version and flags first
          tracks(start, finish) if box == 'moov'
        end
        required = image ? 'meta' : 'moov'
        malformed!("no #{required} box") unless top[required]
        malformed!('no image dimensions') if image && !@dimensions
      end
    end

  private

    attr_reader :policy

    # Yields (type, payload_start, payload_end) for each box in [from, to), seeking past each one.
    def each_box(from, to)
      pos = from
      while pos < to
        malformed!('truncated box header') if to - pos < 8
        @io.seek(pos)
        size, box = @io.read(8).unpack('Na4')
        header = 8
        if size == 1 # 64-bit size follows
          malformed!('truncated box header') if to - pos < 16
          size = @io.read(8).unpack1('Q>')
          header = 16
        elsif size.zero? # box runs to the end of its parent
          size = to - pos
        end
        malformed!("box type #{box.inspect}") unless box.match?(BOX_TYPE)
        malformed!("#{box} box length") if size < header || pos + size > to

        yield box, pos + header, pos + size
        pos += size
      end
    end

    def check_ftyp!(type, start, finish)
      malformed!('ftyp length') if finish - start < 8 || (finish - start) % 4 != 0
      brands = read(start, finish - start).unpack('a4x4a*')
      brands = [brands[0], *brands[1].scan(/.{4}/mn)]
      return if brands.intersect?(BRANDS.fetch(type))

      reject!(:media_brand_mismatch, "brands #{brands.join(',').inspect} are not #{type}")
    end

    # meta > iprp > ipco > ispe: the declared size of every image item.
    def image_properties(start, finish)
      malformed!('meta length') if start > finish
      children(start, finish, 'iprp') do |iprp_start, iprp_end|
        children(iprp_start, iprp_end, 'ipco') do |ipco_start, ipco_end|
          children(ipco_start, ipco_end, 'ispe') do |ispe_start, ispe_end|
            malformed!('ispe length') if ispe_end - ispe_start < 12
            check_pixels!(*read(ispe_start + 4, 8).unpack('NN'))
          end
        end
      end
    end

    # moov > trak > tkhd: width and height (16.16 fixed point) at the end of the track header.
    # Audio and metadata tracks declare 0x0 and are skipped.
    def tracks(start, finish)
      children(start, finish, 'trak') do |trak_start, trak_end|
        children(trak_start, trak_end, 'tkhd') do |tkhd_start, tkhd_end|
          malformed!('tkhd length') if tkhd_end - tkhd_start < 1
          offset = read(tkhd_start, 1).ord == 1 ? 88 : 76
          malformed!('tkhd length') if tkhd_end - tkhd_start < offset + 8
          width, height = read(tkhd_start + offset, 8).unpack('NN').map { |fixed| fixed >> 16 }
          check_pixels!(width, height) unless width.zero? && height.zero?
        end
      end
    end

    def children(start, finish, wanted)
      each_box(start, finish) { |box, child_start, child_end| yield child_start, child_end if box == wanted }
    end

    def check_pixels!(width, height)
      malformed!('zero dimension') if width.zero? || height.zero?
      @dimensions = true
      return if width * height <= policy.max_image_pixels

      reject!(:image_too_many_pixels, "#{width}x#{height} exceeds #{policy.max_image_pixels} pixels")
    end

    def read(offset, length)
      @io.seek(offset)
      data = @io.read(length)
      data && data.bytesize == length ? data : malformed!('truncated')
    end

    def malformed!(what)
      reject!(:media_malformed, what)
    end
  end
end
