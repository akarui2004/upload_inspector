# frozen_string_literal: true

module UploadInspector
  # Minimal reader for Compound File Binary containers (legacy .doc/.xls/.ppt/.msg, encrypted
  # OOXML). Reads the header, the FAT and the directory, and the bytes of a stream on request.
  #
  # Every sector number, chain and size is bounds-checked; a loop, an out-of-range sector or a
  # size larger than the file raises Rejection(:ole_malformed). Nothing is decoded beyond that.
  class CfbReader
    include Rejectable

    MAGIC = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1".b
    TYPE = 'application/x-ole-storage'
    HEADER_SIZE = 512
    DIRECTORY_ENTRY_SIZE = 128
    END_OF_CHAIN = 0xFFFFFFFE
    FREE_SECT = 0xFFFFFFFF
    NO_STREAM = 0xFFFFFFFF
    HEADER_DIFAT_ENTRIES = 109
    STORAGE = 1
    STREAM = 2
    ROOT = 5

    # name is UTF-8 (lossy), type STORAGE/STREAM/ROOT, start the first sector, size in bytes.
    Entry = Data.define(:name, :type, :start, :size) do
      def stream? = type == STREAM
    end

    attr_reader :entries

    def initialize(path)
      @file = File.open(path, 'rb')
      @file_size = @file.size
      read_header!
      @fat = read_fat!
      @entries = read_directory!
      @mini_fat = read_mini_fat!
    end

    def close = @file.close

    def self.open(path)
      reader = new(path)
      yield reader
    ensure
      reader&.close
    end

    # First +limit+ bytes of a stream (all of it when shorter).
    def read(entry, limit)
      length = [entry.size, limit].min
      return ''.b if length.zero?

      read_chain(entry.start, length, mini: entry.stream? && entry.size < @mini_cutoff)
    end

  private

    def read_header!
      header = @file.read(HEADER_SIZE).to_s
      malformed!('truncated header') if header.bytesize < HEADER_SIZE || !header.start_with?(MAGIC)

      major, byte_order, sector_shift, mini_shift = header.unpack('@26v v v v')
      malformed!('byte order') unless byte_order == 0xFFFE
      malformed!('sector size') unless [[3, 9], [4, 12]].include?([major, sector_shift]) && mini_shift == 6

      @sector_size = 1 << sector_shift
      @sector_count = (@file_size - HEADER_SIZE) / @sector_size # sectors start right after the header
      @fat_sectors, @dir_start, @mini_cutoff, @mini_fat_start, @mini_fat_count, @difat_start, @difat_count =
        header.unpack('@44V V @56V V V V V')
      malformed!('mini stream cutoff') unless @mini_cutoff == 4096
      @header_difat = header.unpack("@76V#{HEADER_DIFAT_ENTRIES}")
    end

    # FAT sector numbers come from the header and the DIFAT chain.
    def read_fat!
      malformed!('FAT sector count') if @fat_sectors > @sector_count
      ids = @header_difat.first(@fat_sectors)
      sector = @difat_start
      @difat_count.times do
        break if ids.size >= @fat_sectors

        check_sector!(sector)
        values = read_at(sector_offset(sector), @sector_size).unpack('V*')
        ids.concat(values[0...-1])
        sector = values.last
      end
      ids = ids.first(@fat_sectors)
      malformed!('FAT shorter than declared') if ids.size < @fat_sectors

      ids.each { |id| check_sector!(id) }
      ids.map { |id| read_at(sector_offset(id), @sector_size) }.join.unpack('V*')
    end

    def read_directory!
      data = read_chain(@dir_start)
      entries = (0...(data.bytesize / DIRECTORY_ENTRY_SIZE)).map do |index|
        parse_entry(data.byteslice(index * DIRECTORY_ENTRY_SIZE, DIRECTORY_ENTRY_SIZE))
      end
      malformed!('no root entry') unless entries.first&.type == ROOT
      @root = entries.first
      entries.reject { |entry| entry.type.zero? }
    end

    def parse_entry(raw)
      name_length, type = raw.unpack('@64v C')
      name_length = name_length.clamp(2, 64)
      name = raw.byteslice(0, name_length - 2).force_encoding(Encoding::UTF_16LE).encode('UTF-8', invalid: :replace, undef: :replace)
      start, low, high = raw.unpack('@116V V V')
      # Version 3 files leave the high size word undefined.
      size = @sector_size == 512 ? low : (high << 32) | low
      malformed!("entry type #{type}") unless [0, STORAGE, STREAM, ROOT].include?(type)
      malformed!("stream #{name} larger than the file") if type != STORAGE && size > @file_size

      Entry.new(name:, type:, start:, size:)
    end

    def read_mini_fat!
      return [] if @mini_fat_count.zero? || @mini_fat_start == END_OF_CHAIN

      read_chain(@mini_fat_start).unpack('V*')
    end

    # Streams under the mini stream cutoff live in 64-byte sectors inside the root entry's stream.
    def mini_stream
      @mini_stream ||= read_chain(@root.start, @root.size)
    end

    # Follows a sector chain until +length+ bytes are read (the whole chain when nil).
    # A loop or a sector outside the file or the table is malformed; so is a stream whose
    # chain ends before its declared size.
    def read_chain(start, length = nil, mini: false)
      table = mini ? @mini_fat : @fat
      size = mini ? 64 : @sector_size
      data = +''.b
      seen = {}
      sector = start
      while (length.nil? || data.bytesize < length) && sector != END_OF_CHAIN
        malformed!('sector chain loop') if seen[sector]
        malformed!('sector out of range') if sector >= table.size

        seen[sector] = true
        data << (mini ? mini_sector(sector) : read_at(sector_offset(sector), size))
        sector = table[sector]
      end
      malformed!('chain shorter than the stream') if length && data.bytesize < length
      length ? data.byteslice(0, length) : data
    end

    def mini_sector(sector)
      chunk = mini_stream.byteslice(sector * 64, 64)
      malformed!('mini sector out of range') if chunk.nil? || chunk.bytesize < 64
      chunk
    end

    def check_sector!(sector)
      malformed!('sector out of range') if sector >= @sector_count
    end

    def sector_offset(sector) = HEADER_SIZE + (sector * @sector_size)

    def read_at(offset, length)
      malformed!('sector out of range') if offset + length > @file_size
      @file.seek(offset)
      data = @file.read(length).to_s
      malformed!('truncated sector') if data.bytesize < length
      data
    end

    def malformed!(detail) = reject!(:ole_malformed, detail)
  end
end
