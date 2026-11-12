# frozen_string_literal: true

module UploadInspector
  # Rejects PDFs (and PDF-based formats such as .ai) that carry active content.
  #
  # Streams the raw bytes looking for dangerous name tokens (hex-escaped spellings
  # like /J#61vaScript included), then inflates every compressed object stream
  # (/Type /ObjStm), where those keys could otherwise hide. Nothing is rendered.
  class PdfInspector
    include Rejectable

    CHUNK_SIZE = 4 * MEGABYTE
    INFLATE_CHUNK_SIZE = 64 * 1024
    OVERLAP = 256 # longer than the longest fully hex-escaped token
    OBJECT_WINDOW = 8 * 1024

    ACTIVE_NAMES = %w[
      JavaScript JS Launch EmbeddedFile EmbeddedFiles RichMedia XFA
      SubmitForm ImportData GoToR GoToE Rendition
    ].freeze
    PDF_DELIMITER = '(?=[\s\x00\/<>\[\]()%{}]|\z)'

    # PDF name token matching both literal and #xx-escaped characters.
    def self.name_pattern(name)
      chars = name.chars.map do |char|
        hex = format('%02x', char.ord).chars.map { |h| h.match?(/[a-f]/) ? "[#{h}#{h.upcase}]" : h }.join
        "(?:#{Regexp.escape(char)}|##{hex})"
      end
      "/#{chars.join}#{PDF_DELIMITER}"
    end

    ACTIVE_PATTERN = Regexp.new(ACTIVE_NAMES.map { |n| name_pattern(n) }.join('|'), Regexp::NOENCODING)
    ENCRYPT_PATTERN = Regexp.new(name_pattern('Encrypt'), Regexp::NOENCODING)
    OBJSTM_PATTERN = Regexp.new(name_pattern('ObjStm'), Regexp::NOENCODING)
    OBJECT_HEADER = /\d+\s+\d+\s+obj\b/n
    STREAM_KEYWORD = /stream(?:\r\n|\n|\r)/n

    def initialize(policy)
      @policy = policy
    end

    def verify!(path)
      object_stream_offsets = scan_raw!(path)
      File.open(path, 'rb') do |file|
        object_stream_offsets.each { |offset| inspect_object_stream!(file, offset) }
      end
    end

  private

    attr_reader :policy

    # Returns byte offsets of every /ObjStm token.
    def scan_raw!(path)
      offsets = []
      carry = ''.b
      consumed = 0
      File.open(path, 'rb') do |file|
        while (chunk = file.read(CHUNK_SIZE))
          buffer = carry + chunk
          base = consumed - carry.bytesize
          scan_tokens!(buffer)
          buffer.scan(OBJSTM_PATTERN) { offsets << base + Regexp.last_match.begin(0) }
          carry = tail(buffer)
          consumed += chunk.bytesize
        end
      end
      offsets.uniq
    end

    def scan_tokens!(buffer)
      reject!(:pdf_encrypted, 'encrypted PDF cannot be inspected') if buffer.match?(ENCRYPT_PATTERN)
      match = buffer.match(ACTIVE_PATTERN)
      reject!(:pdf_active_content, decode_name(match[0])) if match
    end

    def inspect_object_stream!(file, offset)
      start = [offset - OBJECT_WINDOW, 0].max
      file.seek(start)
      before = file.read(offset - start) || ''.b
      header_index = before.rindex(OBJECT_HEADER) || reject!(:pdf_unparsable, 'object stream header not found')
      file.seek(offset)
      after = file.read(OBJECT_WINDOW) || ''.b
      stream_match = after.match(STREAM_KEYWORD) || reject!(:pdf_unparsable, 'object stream data not found')

      dictionary = before.byteslice(header_index..) + after.byteslice(0, stream_match.begin(0))
      return unless compressed_object_stream?(dictionary)

      inflate_and_scan!(file, offset + stream_match.end(0))
    end

    # Only a single plain FlateDecode filter is accepted; anything else cannot be verified.
    # Returns false for an unfiltered stream (its bytes were already covered by the raw scan).
    def compressed_object_stream?(dictionary)
      reject!(:pdf_unparsable, 'object stream spans objects') if dictionary.match?(/endobj|endstream/n)
      reject!(:pdf_unparsable, 'escaped names in object stream dictionary') if dictionary.include?('#')
      reject!(:pdf_unparsable, 'object stream decode parameters') if dictionary.include?('/DecodeParms')

      filters = dictionary.scan(%r{/Filter\s*(\[[^\]]*\]|/[A-Za-z0-9]+)}n).flatten
      return false if filters.empty?
      return true if filters.size == 1 && filters.first.gsub(/[\[\]\s]/n, '') == '/FlateDecode'

      reject!(:pdf_unparsable, "unsupported object stream filter #{filters.join(' ')}")
    end

    def inflate_and_scan!(file, data_offset)
      file.seek(data_offset)
      inflater = Zlib::Inflate.new
      inflated = 0
      carry = ''.b
      until inflater.finished?
        chunk = file.read(INFLATE_CHUNK_SIZE) || reject!(:pdf_unparsable, 'truncated object stream')
        output = inflater.inflate(chunk)
        inflated += output.bytesize
        reject!(:pdf_inflate_limit, "object stream exceeds #{policy.max_inflate_size} bytes") if inflated > policy.max_inflate_size
        buffer = carry + output
        scan_tokens!(buffer)
        carry = tail(buffer)
      end
    rescue Zlib::Error => e
      reject!(:pdf_unparsable, "object stream: #{e.message}")
    ensure
      inflater&.close
    end

    def tail(buffer)
      buffer.bytesize > OVERLAP ? buffer.byteslice(-OVERLAP, OVERLAP) : buffer
    end

    def decode_name(token)
      token.gsub(/#(\h\h)/n) { Regexp.last_match(1).hex.chr }
    end
  end
end
