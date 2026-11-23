# frozen_string_literal: true

module UploadInspector
  # Rejects PDFs (and PDF-based formats such as .ai) that carry active content.
  #
  # Streams the raw bytes looking for dangerous name tokens (hex-escaped spellings like
  # /J#61vaScript included). Object streams, where dictionaries can hide compressed, are
  # located by their /ObjStm and /First markers, parsed with a real PDF lexer and inflated.
  # URI actions may only point to web or mail addresses, and may not run on their own when the
  # document or a page opens (/OpenAction, /AA). Links are collected for Result#links, or
  # rejected with pdf_links: :reject. Nothing is rendered.
  class PdfInspector
    include Rejectable
    include LinkCollector

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
    AUTO_ACTION_PATTERN = names_regexp('OpenAction', 'AA')
    OBJECT_HEADER = /\d+[\0\t\n\f\r ]+\d+[\0\t\n\f\r ]+obj\b/n
    NUMBERED_HEADER = /(?<!\d)(\d+)[\0\t\n\f\r ]+(\d+)[\0\t\n\f\r ]+obj(?=[\0\t\n\f\r \/<\[(%])/n
    # Values worth following: a dictionary or an indirect reference. Anything else after /AA or
    # /OpenAction is a destination array or stray bytes in binary data.
    ACTION_VALUE = /\A(?:[\0\t\n\f\r ]|%[^\r\n]*)*(?:<<|\d+[\0\t\n\f\r ]+\d+[\0\t\n\f\r ]+R)/n
    MAX_ACTION_DEPTH = 16
    MAX_ACTION_NODES = 1_000 # objects visited while following automatic actions
    NAME_TOKEN = %r{\A/[^\0\t\n\f\r ()<>\[\]{}/%]*}n
    VALUE_END = /\A(?:[\0\t\n\f\r ]|%[^\r\n]*)*(?:>>|\]|\z)/n

    def initialize(policy, links: [])
      @policy = policy
      @links = links
    end

    def verify!(path)
      markers, uris, actions = scan_raw!(path)
      File.open(path, 'rb') do |file|
        @file = file
        uris.each { |offset| check_uri!(read_at(file, offset, VALUE_WINDOW), 0) }
        inspected = []
        @stream_objects = Hash.new { |hash, key| hash[key] = [] } # object number => [[stream data, offset]]
        @stream_actions = [] # [stream data, offset] of /OpenAction and /AA inside object streams
        markers.each { |offset| inspect_marker!(file, offset, inspected) }
        # Followed only once every object stream is indexed, so references into them resolve.
        @visited = {}
        actions.each { |offset| check_auto_action!(read_at(file, offset, VALUE_WINDOW), 0) }
        @stream_actions.each { |data, offset| check_auto_action!(data, offset) }
      end
    end

  private

    attr_reader :policy

    # Returns byte offsets of object stream markers, URI keys and automatic action keys, and
    # indexes where each numbered object is defined (all definitions: incremental updates).
    def scan_raw!(path)
      markers = []
      uris = []
      actions = []
      @objects = Hash.new { |hash, key| hash[key] = [] }
      carry = ''.b
      consumed = 0
      File.open(path, 'rb') do |file|
        while (chunk = file.read(CHUNK_SIZE))
          buffer = carry + chunk
          base = consumed - carry.bytesize
          scan_tokens!(buffer)
          buffer.scan(OBJSTM_MARKER) { markers << base + Regexp.last_match.begin(0) }
          buffer.scan(URI_PATTERN) { uris << base + Regexp.last_match.begin(0) }
          buffer.scan(AUTO_ACTION_PATTERN) { actions << base + Regexp.last_match.begin(0) }
          buffer.scan(NUMBERED_HEADER) do
            match = Regexp.last_match
            @objects[[match[1].to_i, match[2].to_i]] |= [base + match.begin(0)]
          end
          carry = tail(buffer)
          consumed += chunk.bytesize
        end
      end
      [markers.uniq, uris.uniq, actions.uniq]
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
      if compressed_object_stream?(object.value)
        inflate_and_scan!(file, start + object.stream_start, object.value)
      else
        @unindexed_object_stream = true
      end
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
    def inflate_and_scan!(file, data_offset, dictionary)
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
      output.scan(AUTO_ACTION_PATTERN) { @stream_actions << [output, Regexp.last_match.begin(0)] }
      index_stream_objects(output, dictionary)
    rescue Zlib::Error => e
      reject!(:pdf_unparsable, "object stream: #{e.message}")
    ensure
      inflater&.close
    end

    # An object stream starts with /N pairs "object-number offset", offsets counted from /First.
    def index_stream_objects(data, dictionary)
      first = dictionary['First'].to_s.to_i
      count = dictionary['N'].to_s.to_i
      data.byteslice(0, first).to_s.scan(/\d+/n).map(&:to_i).each_slice(2).first(count).each do |number, offset|
        @stream_objects[number] << [data, first + offset.to_i]
      end
    end

    # +offset+ points at a /URI name; its value must be a web/mail link (or a name or dictionary
    # holding one, e.g. the catalog's /URI << /Base (...) >>). Indirect values cannot be checked.
    def check_uri!(buffer, offset)
      value_offset = offset + buffer.byteslice(offset, OVERLAP)[NAME_TOKEN].bytesize
      return if buffer.byteslice(value_offset, OVERLAP).match?(VALUE_END) # /URI used as a value: /S /URI >>

      value = PdfObjectParser.new(buffer, value_offset).parse_value_at
      base = value.is_a?(Hash)
      value = value['Base'] if base
      case value
      when PdfObjectParser::PdfString
        text = uri_text(value.bytes)
        reject!(:pdf_unsafe_uri, value.bytes.inspect) unless text && safe_uri?(text)
        record_link!(text) unless base
      when PdfObjectParser::Ref
        reject!(:pdf_unsafe_uri, 'indirect URI value')
      end
    end

    def record_link!(text)
      reject!(:pdf_link, text[0, 80]) if policy.pdf_links == :reject
      add_link(text)
    end

    # Readers and browsers drop whitespace/control characters inside URLs ("java\tscript:"),
    # so they are removed. nil when a UTF-16 string does not decode.
    def uri_text(bytes)
      text = bytes.start_with?("\xFE\xFF".b) ? bytes.byteslice(2..).force_encoding('UTF-16BE').encode('UTF-8') : bytes
      text.b.gsub(/[\x00-\x20\x7F]/n, '')
    rescue EncodingError
      nil
    end

    # Relative links have no scheme and pass.
    def safe_uri?(text)
      return false if text.start_with?('\\\\', '//')

      scheme = text[/\A([A-Za-z][A-Za-z0-9+.\-]*):/n, 1]
      scheme.nil? || SAFE_URI_SCHEMES.include?(scheme.downcase)
    end

    # +offset+ points at /OpenAction or /AA. A URI action they reach (directly, through indirect
    # objects or /Next chains) opens a link with no click, which phishing PDFs rely on.
    def check_auto_action!(buffer, offset)
      name = buffer.byteslice(offset, OVERLAP)[NAME_TOKEN]
      value_offset = offset + name.bytesize
      return unless buffer.byteslice(value_offset, OVERLAP).match?(ACTION_VALUE)

      value = PdfObjectParser.new(buffer, value_offset).parse_value_at
      follow_action!(value, decode_name(name) == '/AA' ? :triggers : :action, 0)
    end

    # :triggers is an /AA dictionary (event => action); :action an action, or a destination
    # (an array, ignored) behind /OpenAction.
    def follow_action!(value, kind, depth)
      reject!(:pdf_unparsable, 'action chain too deep') if depth > MAX_ACTION_DEPTH
      if value.is_a?(PdfObjectParser::Ref)
        return if @visited[[value, kind]] # shared or cyclic references are checked once

        @visited[[value, kind]] = true
        reject!(:pdf_unparsable, 'too many objects behind automatic actions') if @visited.size > MAX_ACTION_NODES
        return resolve(value).each { |object| follow_action!(object, kind, depth + 1) }
      end
      return unless value.is_a?(Hash)

      if kind == :triggers
        value.each_value { |action| follow_action!(action, :action, depth + 1) }
      else
        reject!(:pdf_auto_action, 'opens a link when the document or a page opens') if value['S'] == PdfObjectParser::Name.new('URI')
        following = value['Next']
        (following.is_a?(Array) ? following : [following]).each { |action| follow_action!(action, :action, depth + 1) }
      end
    end

    # Every definition of the object, in the file or in a compressed object stream (always
    # generation 0); a reader picks one through the xref table, so all of them are checked. A
    # missing object is null to readers, unless it may sit in an object stream we did not inflate.
    def resolve(ref)
      raw = @objects.fetch([ref.number, ref.generation], []).map do |offset|
        PdfObjectParser.new(read_at(@file, offset, VALUE_WINDOW), 0).parse_object.value
      end
      streamed = ref.generation.zero? ? @stream_objects.fetch(ref.number, []) : []
      objects = raw + streamed.map { |data, offset| PdfObjectParser.new(data, offset).parse_value_at }
      reject!(:pdf_unparsable, 'action behind an uncompressed object stream') if objects.empty? && @unindexed_object_stream
      objects
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
