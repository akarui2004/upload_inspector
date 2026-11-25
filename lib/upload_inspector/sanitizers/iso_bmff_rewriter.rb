# frozen_string_literal: true

module UploadInspector
  module Sanitizers
    # Rewrites a HEIC / HEIF / AVIF image or MP4 / QuickTime video that passed the check.
    #
    # Sample tables (stco/co64), item locations (iloc) and fragment indexes (tfra, sidx) hold
    # absolute file offsets, so no byte may move. Whatever is removed is therefore overwritten
    # in place by a zero-filled `free` box of the same size (or zeros, inside item data), except
    # top-level boxes that nothing follows, which are dropped:
    # - top-level boxes other than KEPT (free, skip, uuid such as XMP, unknown)
    # - user data and metadata inside moov and its tracks (udta, meta: titles, comments, GPS
    #   location of phone videos) and their free/skip/uuid boxes
    # - Exif and XMP items of an image (camera data, GPS): their data is zeroed and their item
    #   type renamed, so readers no longer look for metadata there
    #
    # Not covered: data inside mdat that no sample or item refers to.
    class IsoBmffRewriter
      include Rejectable

      KEPT = %w[ftyp moov mdat meta moof mfra sidx ssix styp prft].freeze
      MOVIE_METADATA = %r{\Amoov/(?:trak/)?(?:udta|meta|free|skip|uuid)\z}
      METADATA_ITEM_TYPES = %w[Exif mime].freeze # mime: XMP (application/rdf+xml)
      REMOVED_ITEM_TYPE = 'skip'
      ZEROS = ("\0" * MEGABYTE).b.freeze

      def initialize(policy)
        @policy = policy
      end

      # Writes the rewritten file of +path+ (detected +type+) to +output+.
      def rewrite(path, type, output)
        boxes = []
        IsoBmffInspector.new(@policy).verify!(path, type) { |*box| boxes << box }
        File.open(path, 'rb') do |io|
          @io = io
          top = boxes.reject { |box, *| box.include?('/') }
          last_kept = top.rindex { |box, *| KEPT.include?(box) }
          File.open(output, 'wb') do |out|
            top.each_with_index do |(box, offset, length, header), index|
              if KEPT.include?(box) then IO.copy_stream(io, out, length, offset)
              elsif index < last_kept then write_free(out, length, header)
              end
            end
            # Offsets in the output equal those in the source: only trailing boxes were dropped.
            boxes.each { |box, offset, length, header| overwrite_free(out, offset, length, header) if box.match?(MOVIE_METADATA) }
            metadata_items(boxes).each do |offset, length, replacement|
              out.seek(offset)
              replacement ? out.write(replacement) : write_zeros(out, length)
            end
          end
        end
      end

    private

      def overwrite_free(out, offset, length, header)
        out.seek(offset)
        write_free(out, length, header)
      end

      # Same total size and header form (32- or 64-bit size) as the box it replaces.
      def write_free(out, length, header)
        out.write(header == 16 ? [1, 'free', length].pack('Na4Q>') : [length, 'free'].pack('Na4'))
        write_zeros(out, length - header)
      end

      def write_zeros(out, remaining)
        remaining -= out.write(ZEROS.byteslice(0, [remaining, ZEROS.bytesize].min)) while remaining.positive?
      end

      # [offset, length, replacement] to overwrite: the item type field of every Exif/XMP item
      # (renamed: data of zeros is not valid Exif) and, replacement nil, its data (zeroed).
      def metadata_items(boxes)
        find = ->(name) { boxes.find { |box, *| box == name } }
        iinf = find['meta/iinf']
        iloc = find['meta/iloc']
        return [] unless iinf && iloc

        types = item_types(iinf)
        ids = types.filter_map { |id, (type, _)| id if METADATA_ITEM_TYPES.include?(type) }
        return [] if ids.empty?

        renames = ids.map { |id| [types[id][1], 4, REMOVED_ITEM_TYPE] }
        extents = item_extents(iloc, find['meta/idat'], ids)
        renames + extents
      end

      # { item_ID => [item_type, offset of the type field] } from infe version 2 and 3 entries.
      def item_types(iinf)
        _, offset, length, header = iinf
        payload = read(offset + header, length - header)
        position = payload.getbyte(0).zero? ? 6 : 8 # FullBox, then a 16- or 32-bit entry count
        types = {}
        while position + 8 <= payload.bytesize
          size, box = payload.byteslice(position, 8).unpack('Na4')
          malformed!('infe length') if size < 8 || position + size > payload.bytesize
          entry = payload.byteslice(position + 8, size - 8)
          if box == 'infe' && [2, 3].include?(entry.getbyte(0))
            id_format, type_at = entry.getbyte(0) == 2 ? ['n', 8] : ['N', 10]
            id = entry.byteslice(4, 4).unpack1(id_format)
            types[id] = [entry.byteslice(type_at, 4), offset + header + position + 8 + type_at] if entry.bytesize >= type_at + 4
          end
          position += size
        end
        types
      end

      # Absolute [offset, length] of every extent of the +ids+ items (ISO/IEC 14496-12 iloc).
      def item_extents(iloc, idat, ids)
        _, offset, length, header = iloc
        @iloc = read(offset + header, length - header)
        @position = 4 # FullBox version and flags
        version = @iloc.getbyte(0).to_i
        sizes = take(2)
        offset_size = sizes >> 12
        length_size = (sizes >> 8) & 0xF
        base_offset_size = (sizes >> 4) & 0xF
        index_size = version.zero? ? 0 : sizes & 0xF
        id_size = version < 2 ? 2 : 4

        ranges = []
        take(id_size).times do
          id = take(id_size)
          method = version.zero? ? 0 : take(2) & 0xF
          data_reference = take(2)
          base = take(base_offset_size)
          take(2).times do
            take(index_size)
            extent_offset = take(offset_size)
            extent_length = take(length_size)
            next unless ids.include?(id)

            unsupported!('metadata item in another file or item') if data_reference.positive? || method > 1
            unsupported!('metadata item running to the end of the file') if extent_length.zero?
            start = base + extent_offset
            start += idat[1] + idat[3] if method == 1 # inside the idat box of meta
            malformed!('metadata item outside the file') if method == 1 && !idat
            malformed!('metadata item outside the file') if start + extent_length > @io.size
            ranges << [start, extent_length]
          end
        end
        ranges
      end

      # Big-endian unsigned integer of +size+ bytes (0, 1, 2, 4 or 8) from the iloc payload.
      def take(size)
        return 0 if size.zero?

        bytes = @iloc.byteslice(@position, size)
        malformed!('iloc length') unless bytes&.bytesize == size
        @position += size
        bytes.unpack1({ 1 => 'C', 2 => 'n', 4 => 'N', 8 => 'Q>' }.fetch(size) { malformed!('iloc field size') })
      end

      def read(offset, length)
        @io.seek(offset)
        @io.read(length).to_s
      end

      def unsupported!(what) = reject!(:sanitize_unsupported, what)
      def malformed!(what) = reject!(:media_malformed, what)
    end
  end
end
