# frozen_string_literal: true

require 'strscan'

module UploadInspector
  # Minimal PDF lexer/parser for one indirect object ("N G obj <value> [stream|endobj]").
  #
  # It exists so the inspector sees a dictionary the way a reader does: comments, literal
  # strings (nested parentheses, escapes) and hex strings are real tokens, not text a regex
  # can be fooled by. Anything malformed or truncated raises Rejection (fail closed).
  class PdfObjectParser
    include Rejectable

    Name = Data.define(:value)
    Ref = Data.define(:number, :generation)
    PdfString = Data.define(:bytes)
    # value         - parsed object value (Hash for dictionaries)
    # stream_start  - offset of the first stream data byte, nil for non-stream objects
    # name_offsets  - offsets of names that are keys or values of the top-level dictionary
    # has_text      - a comment or string appeared inside the object
    # end_offset    - offset just past the stream keyword or endobj
    ParsedObject = Data.define(:value, :stream_start, :end_offset, :name_offsets, :has_text)

    WHITESPACE = /[\0\t\n\f\r ]+/n
    COMMENT = /%[^\r\n]*/n
    HEADER = /\d+[\0\t\n\f\r ]+\d+[\0\t\n\f\r ]+obj(?=[\0\t\n\f\r \/<\[(%])/n
    NAME = %r{/[^\0\t\n\f\r ()<>\[\]{}/%]*}n
    NUMBER = /[+-]?(?:\d+\.?\d*|\.\d+)/n
    REF = /(\d+)[\0\t\n\f\r ]+(\d+)[\0\t\n\f\r ]+R(?![^\0\t\n\f\r ()<>\[\]{}\/%])/n
    KEYWORD = /(?:true|false|null)(?![^\0\t\n\f\r ()<>\[\]{}\/%])/n
    STREAM = /stream(?:\r\n|\n|\r)/n
    ENDOBJ = /endobj/n
    MAX_DEPTH = 64
    ESCAPES = { 'n' => "\n", 'r' => "\r", 't' => "\t", 'b' => "\b", 'f' => "\f" }.freeze

    def initialize(buffer, offset)
      @scanner = StringScanner.new(buffer)
      @scanner.pos = offset
      @name_offsets = []
      @has_text = false
    end

    def parse_object
      @scanner.scan(HEADER) || fail!('object header')
      value = parse_value(0)
      skip_space
      stream_start = @scanner.pos if @scanner.scan(STREAM)
      @scanner.scan(ENDOBJ) || fail!('stream or endobj') unless stream_start
      ParsedObject.new(value:, stream_start:, end_offset: @scanner.pos, name_offsets: @name_offsets, has_text: @has_text)
    end

    # Parses a single value at +offset+ (used for values that follow a known key).
    def parse_value_at
      parse_value(1)
    end

    # Decodes a literal string body (between the outer parentheses) per PDF escape rules.
    def self.unescape(raw)
      raw.gsub(/\\(?:([0-7]{1,3})|(\r\n|\r|\n)|(.))/mn) do
        if Regexp.last_match(1) then (Regexp.last_match(1).to_i(8) & 0xFF).chr
        elsif Regexp.last_match(2) then ''
        else ESCAPES.fetch(Regexp.last_match(3), Regexp.last_match(3))
        end
      end
    end

  private

    def parse_value(depth)
      fail!('nesting too deep') if depth > MAX_DEPTH
      skip_space
      if @scanner.scan(/<</n) then parse_dictionary(depth)
      elsif @scanner.scan(/\[/n) then parse_array(depth)
      elsif @scanner.check(/</n) then parse_hex_string
      elsif @scanner.check(/\(/n) then parse_literal_string
      elsif (name = @scanner.scan(NAME)) then Name.new(decode_name(name))
      elsif @scanner.scan(REF) then Ref.new(@scanner[1].to_i, @scanner[2].to_i)
      elsif (number = @scanner.scan(NUMBER)) then number
      elsif (keyword = @scanner.scan(KEYWORD)) then keyword
      else fail!('unexpected token')
      end
    end

    def parse_dictionary(depth)
      entries = {}
      loop do
        skip_space
        return entries if @scanner.scan(/>>/n)

        key_offset = @scanner.pos
        key = @scanner.scan(NAME) || fail!('dictionary key')
        value_offset = skip_space
        value = parse_value(depth + 1)
        if depth.zero?
          @name_offsets << key_offset
          @name_offsets << value_offset if value.is_a?(Name)
        end
        entries[decode_name(key)] = value
      end
    end

    def parse_array(depth)
      items = []
      loop do
        skip_space
        return items if @scanner.scan(/\]/n)

        items << parse_value(depth + 1)
      end
    end

    # Hex strings may only hold hex digits and whitespace; readers that skip other bytes
    # would otherwise see a different token stream than we do.
    def parse_hex_string
      @has_text = true
      body = @scanner.scan(/<([0-9A-Fa-f\0\t\n\f\r ]*)>/n) || fail!('hex string')
      hex = body[1...-1].gsub(WHITESPACE, '')
      hex << '0' if hex.size.odd?
      PdfString.new([hex].pack('H*'))
    end

    def parse_literal_string
      @has_text = true
      start = @scanner.pos + 1
      @scanner.pos = start
      depth = 1
      while depth.positive?
        @scanner.scan_until(/[()\\]/n) || fail!('unterminated string')
        case @scanner.matched
        when '\\' then @scanner.getch || fail!('unterminated string')
        when '(' then depth += 1
        when ')' then depth -= 1
        end
      end
      PdfString.new(self.class.unescape(@scanner.string.byteslice(start...(@scanner.pos - 1))))
    end

    # Returns the position after whitespace and comments.
    def skip_space
      loop do
        @scanner.scan(WHITESPACE)
        break unless @scanner.scan(COMMENT)

        @has_text = true
      end
      @scanner.pos
    end

    def decode_name(token)
      token.byteslice(1..).gsub(/#(\h\h)/n) { Regexp.last_match(1).hex.chr }
    end

    def fail!(what)
      reject!(:pdf_unparsable, "malformed object (#{what})")
    end
  end
end
