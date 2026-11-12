# frozen_string_literal: true

module UploadInspector
  # Rejects PDFs (and PDF-based formats such as .ai) that carry active content.
  #
  # Streams the raw bytes looking for dangerous name tokens (hex-escaped spellings like
  # /J#61vaScript included). Object streams, where dictionaries can hide compressed, are
  # located by their /ObjStm and /First markers, parsed with a real PDF lexer and inflated.
  # URI actions may only point to web or mail addresses. Nothing is rendered.
  class PdfInspector
    include Rejectable

    CHUNK_SIZE = 4 * MEGABYTE
    INFLATE_CHUNK_SIZE = 64 * 1024
    OVERLAP = 256 # longer than the longest fully hex-escaped token
    OBJECT_WINDOW = 8 * 1024 # how far back an object header may sit before a marker
    VALUE_WINDOW = 64 * 1024 # how far a parsed value may extend after its key

    ACTIVE_NAMES = %w[
      JavaScript JS Launch EmbeddedFile EmbeddedFiles RichMedia XFA
      SubmitForm ImportData GoToR GoToE Rendition
      EF FileAttachment Filespec Collection
    ].freeze # attachments need neither /Type /EmbeddedFile nor the /EmbeddedFiles name tree, only /EF
    # Not scripts, but parsers with a long exploit history (JBIG2: FORCEDENTRY class; 3D: U3D/PRC).
    RISKY_NAMES = %w[JBIG2Decode 3D U3D PRC].freeze
    SAFE_URI_SCHEMES = %w[http https mailto].freeze
    PDF_DELIMITER = '(?=[\s\x00\/<>\[\]()%{}]|\z)'
    PDF_SPACE = '(?:[\s\x00]|%[^\r\n]*)*'

    # PDF name token matching both literal and #xx-escaped characters.
    def self.name_pattern(name)
      chars = name.chars.map do |char|
        hex = format('%02x', char.ord).chars.map { |h| h.match?(/[a-f]/) ? "[#{h}#{h.upcase}]" : h }.join
        "(?:#{Regexp.escape(char)}|##{hex})"
      end
      "/#{chars.join}#{PDF_DELIMITER}"
    end

    def self.names_regexp(*names) = Regexp.new(names.map { |n| name_pattern(n) }.join('|'), Regexp::NOENCODING)

    ACTIVE_PATTERN = names_regexp(*ACTIVE_NAMES)
    RISKY_PATTERN = names_regexp(*RISKY_NAMES)
    POSTSCRIPT_PATTERN = Regexp.new("(?:#{name_pattern('Subtype')}|#{name_pattern('Subtype2')})#{PDF_SPACE}#{name_pattern('PS')}",
                                    Regexp::NOENCODING)
    ENCRYPT_PATTERN = names_regexp('Encrypt')
    OBJSTM_MARKER = names_regexp('ObjStm', 'First') # readers need /First to load an object stream
    URI_PATTERN = names_regexp('URI')
    OBJECT_HEADER = /\d+[\0\t\n\f\r ]+\d+[\0\t\n\f\r ]+obj\b/n
    NAME_TOKEN = %r{\A/[^\0\t\n\f\r ()<>\[\]{}/%]*}n
    VALUE_END = /\A(?:[\0\t\n\f\r ]|%[^\r\n]*)*(?:>>|\]|\z)/n

    def initialize(policy)
      @policy = policy
    end

    def verify!(path)
      markers, uris = scan_raw!(path)
      File.open(path, 'rb') do |file|
        uris.each { |offset| check_uri!(read_at(file, offset, VALUE_WINDOW), 0) }
        inspected = []
        markers.each { |offset| inspect_marker!(file, offset, inspected) }
      end
    end

  private

    attr_reader :policy

    # Returns byte offsets of object stream markers and URI keys.
    def scan_raw!(path)
      markers = []
      uris = []
      carry = ''.b
      consumed = 0
      File.open(path, 'rb') do |file|
        while (chunk = file.read(CHUNK_SIZE))
          buffer = carry + chunk
          base = consumed - carry.bytesize
          scan_tokens!(buffer)
          buffer.scan(OBJSTM_MARKER) { markers << base + Regexp.last_match.begin(0) }
          buffer.scan(URI_PATTERN) { uris << base + Regexp.last_match.begin(0) }
          carry = tail(buffer)
          consumed += chunk.bytesize
        end
      end
      [markers.uniq, uris.uniq]
    end

    def scan_tokens!(buffer)
      reject!(:pdf_encrypted, 'encrypted PDF cannot be inspected') if buffer.match?(ENCRYPT_PATTERN)
      match = buffer.match(ACTIVE_PATTERN)
      reject!(:pdf_active_content, decode_name(match[0])) if match
      match = buffer.match(RISKY_PATTERN) || buffer.match(POSTSCRIPT_PATTERN)
      reject!(:pdf_risky_feature, decode_name(match[0])) if match
    end

    # A marker counts only as a top-level key/value of a stream dictionary, as parsed from the
    # nearest object header. A header hidden in a comment or string makes the parse disagree
    # with the reader's; that always leaves a comment, a string or a misplaced marker, all rejected.
    def inspect_marker!(file, offset, inspected)
      start = [offset - OBJECT_WINDOW, 0].max
      buffer = read_at(file, start, offset - start + VALUE_WINDOW)
      local = offset - start
      header = buffer.byteslice(0, local).rindex(OBJECT_HEADER) || reject!(:pdf_unparsable, 'object stream header not found')
      line_start = (buffer.rindex(/[\r\n]/n, header) || -1) + 1
      reject!(:pdf_unparsable, 'object header inside a comment') if buffer.byteslice(line_start...header).include?('%')

      object = PdfObjectParser.new(buffer, header).parse_object
      reject!(:pdf_unparsable, 'object stream marker outside a dictionary') if local >= object.end_offset
      return unless object.stream_start && object.name_offsets.include?(local)
      return if inspected.include?(start + object.stream_start)

      inspected << (start + object.stream_start)
      reject!(:pdf_unparsable, 'comment or string in object stream dictionary') if object.has_text
      inflate_and_scan!(file, start + object.stream_start) if compressed_object_stream?(object.value)
    end

    # Only a single plain FlateDecode filter is accepted; anything else cannot be verified.
    # Returns false for an unfiltered stream (its bytes were already covered by the raw scan).
    def compressed_object_stream?(dictionary)
      reject!(:pdf_unparsable, 'object stream decode parameters') if dictionary.key?('DecodeParms')
      filters = Array(dictionary['Filter'])
      return false if filters.empty?
      return true if filters == [PdfObjectParser::Name.new('FlateDecode')]

      shown = filters.map { |f| f.is_a?(PdfObjectParser::Name) ? "/#{f.value}" : f.class.name.split('::').last }
      reject!(:pdf_unparsable, "unsupported object stream filter #{shown.join(' ')}")
    end

    # Inflates fully (bounded by max_inflate_size) so keys and URI values are scanned whole.
    def inflate_and_scan!(file, data_offset)
      file.seek(data_offset)
      inflater = Zlib::Inflate.new
      output = ''.b
      until inflater.finished?
        chunk = file.read(INFLATE_CHUNK_SIZE) || reject!(:pdf_unparsable, 'truncated object stream')
        output << inflater.inflate(chunk)
        reject!(:pdf_inflate_limit, "object stream exceeds #{policy.max_inflate_size} bytes") if output.bytesize > policy.max_inflate_size
      end
      scan_tokens!(output)
      output.scan(URI_PATTERN) { check_uri!(output, Regexp.last_match.begin(0)) }
    rescue Zlib::Error => e
      reject!(:pdf_unparsable, "object stream: #{e.message}")
    ensure
      inflater&.close
    end

    # +offset+ points at a /URI name; its value must be a web/mail link (or a name or dictionary
    # holding one, e.g. the catalog's /URI << /Base (...) >>). Indirect values cannot be checked.
    def check_uri!(buffer, offset)
      value_offset = offset + buffer.byteslice(offset, OVERLAP)[NAME_TOKEN].bytesize
      return if buffer.byteslice(value_offset, OVERLAP).match?(VALUE_END) # /URI used as a value: /S /URI >>

      value = PdfObjectParser.new(buffer, value_offset).parse_value_at
      value = value['Base'] if value.is_a?(Hash)
      case value
      when PdfObjectParser::PdfString
        reject!(:pdf_unsafe_uri, value.bytes.inspect) unless safe_uri?(value.bytes)
      when PdfObjectParser::Ref
        reject!(:pdf_unsafe_uri, 'indirect URI value')
      end
    end

    # Readers and browsers drop whitespace/control characters inside URLs ("java\tscript:"),
    # so they are removed before the scheme is read. Relative links have no scheme and pass.
    def safe_uri?(bytes)
      text = bytes.start_with?("\xFE\xFF".b) ? bytes.byteslice(2..).force_encoding('UTF-16BE').encode('UTF-8') : bytes
      text = text.b.gsub(/[\x00-\x20\x7F]/n, '')
      return false if text.start_with?('\\\\', '//')

      scheme = text[/\A([A-Za-z][A-Za-z0-9+.\-]*):/n, 1]
      scheme.nil? || SAFE_URI_SCHEMES.include?(scheme.downcase)
    rescue EncodingError
      false
    end

    def read_at(file, offset, length)
      file.seek(offset)
      file.read(length) || ''.b
    end

    def tail(buffer)
      buffer.bytesize > OVERLAP ? buffer.byteslice(-OVERLAP, OVERLAP) : buffer
    end

    def decode_name(token)
      token.gsub(/#(\h\h)/n) { Regexp.last_match(1).hex.chr }
    end
  end
end
