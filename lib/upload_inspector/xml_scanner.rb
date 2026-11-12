# frozen_string_literal: true

require 'strscan'

module UploadInspector
  # Forward-only XML tokenizer shared by the OOXML and SVG inspectors.
  #
  # Every byte is consumed exactly once, so hostile input (unclosed tags, unterminated quotes,
  # megabytes of attribute junk) costs linear time. It follows the XML grammar closely enough
  # that a conforming parser sees the same tags: comments, CDATA, processing instructions and
  # quoted attribute values (which may contain ">") are real tokens. Anything a conforming
  # parser would refuse raises Malformed, which callers turn into a rejection (fail closed).
  class XmlScanner
    Malformed = Class.new(StandardError)

    # name is the qualified name ("w:instrText"); raw_attributes the text up to the closing ">".
    Tag = Data.define(:name, :raw_attributes) do
      def local_name = name.split(':').last.to_s
    end

    DTD = /<!DOCTYPE|<!ENTITY/i
    DECLARED_ENCODING = /\A(?:\xEF\xBB\xBF)?<\?xml[^>]*?\bencoding\s*=\s*["']([^"']*)["']/n
    # ASCII-compatible single-byte encodings cannot spell a tag or keyword differently.
    SINGLE_BYTE_ENCODINGS = %w[US-ASCII ISO-8859-1].freeze
    XML_ENTITIES = { 'amp' => '&', 'lt' => '<', 'gt' => '>', 'quot' => '"', 'apos' => "'" }.freeze

    # Patterns below only hold when the bytes mean what they look like: UTF-16/32 and exotic
    # declared encodings would let a reader see different text than the inspector.
    def self.supported_encoding?(xml)
      return false if xml.include?("\0") || xml.start_with?("\xFF\xFE".b, "\xFE\xFF".b)

      declared = xml[DECLARED_ENCODING, 1]
      return true if declared && SINGLE_BYTE_ENCODINGS.any? { |name| declared.casecmp?(name) }

      (declared.nil? || declared.casecmp?('UTF-8')) && xml.dup.force_encoding(Encoding::UTF_8).valid_encoding?
    end

    # Readers act on decoded text, so patterns must run on it too.
    def self.decode_entities(text)
      text.to_s.b
          .gsub(/&#[xX](\h+);/n) { codepoint_bytes(Regexp.last_match(1).hex) }
          .gsub(/&#(\d+);/n) { codepoint_bytes(Regexp.last_match(1).to_i) }
          .gsub(/&(amp|lt|gt|quot|apos);/n) { XML_ENTITIES[Regexp.last_match(1)] }
    end

    # Invalid code points become a marker that never matches an allowed value (fail closed).
    def self.codepoint_bytes(codepoint)
      [codepoint].pack('U').b
    rescue RangeError
      "�".b
    end

    # [[qualified name, entity-decoded value], ...] in document order. Unquoted values, stray
    # text and repeated names are not XML and raise Malformed.
    def self.attributes(tag)
      scanner = StringScanner.new(tag.raw_attributes)
      pairs = []
      seen = {}
      loop do
        scanner.skip(/\s+/n)
        break if scanner.eos? || scanner.skip(%r{/\s*\z}n)

        name = scanner.scan(/[^\s=\/"'<>]+/n) || raise(Malformed, 'attribute name')
        scanner.skip(/\s*=\s*/n) || raise(Malformed, 'attribute without value')
        value = scanner.scan(/"[^"]*"|'[^']*'/n) || raise(Malformed, 'unquoted attribute value')
        raise Malformed, 'duplicate attribute' if seen.key?(name)

        seen[name] = true
        pairs << [name, decode_entities(value[1...-1])]
      end
      pairs
    end

    def initialize(xml)
      @scanner = StringScanner.new(xml)
    end

    # Yields [:open | :empty | :close, Tag], [:text, raw], [:cdata, raw] and [:pi, raw].
    # Text is raw (entities undecoded); CDATA is literal.
    def each(&block)
      depth = 0
      until @scanner.eos?
        text = @scanner.scan(/[^<]+/n)
        yield :text, text if text
        break if @scanner.eos?

        kind = scan_markup(&block)
        depth += 1 if kind == :open
        depth -= 1 if kind == :close
        raise Malformed, 'closing tag without an opening tag' if depth.negative?
      end
      raise Malformed, 'unclosed element' unless depth.zero?
    end

  private

    # Returns :open, :empty or :close for a tag, nil for other markup.
    def scan_markup(&)
      return scan_tag(&) unless @scanner.match?(/<[!?]/n)

      if @scanner.skip(/<!--/n)
        @scanner.skip_until(/-->/n) || raise(Malformed, 'unterminated comment')
      elsif @scanner.skip(/<!\[CDATA\[/n)
        yield :cdata, (@scanner.scan_until(/\]\]>/n) || raise(Malformed, 'unterminated CDATA'))[0...-3]
      elsif @scanner.skip(/<\?/n)
        yield :pi, (@scanner.scan_until(/\?>/n) || raise(Malformed, 'unterminated processing instruction'))[0...-2]
      else
        raise Malformed, 'declaration'
      end
      nil
    end

    def scan_tag
      @scanner.scan(%r{<(/?)([^\s/>"'<=]+)}n) || raise(Malformed, 'tag')
      closing = !@scanner[1].empty?
      name = @scanner[2]
      raw = read_attributes
      kind = if closing then :close
             elsif raw.end_with?('/') then :empty
             else :open
             end
      raise Malformed, 'attributes on a closing tag' if closing && !raw.strip.empty?

      yield kind, Tag.new(name:, raw_attributes: raw)
      kind
    end

    # Quote-aware: ">" inside an attribute value does not end the tag.
    def read_attributes
      raw = +''.b
      loop do
        raw << @scanner.scan(/[^>"']*/n)
        return raw if @scanner.skip(/>/n)

        quote = @scanner.getch || raise(Malformed, 'unterminated tag')
        raw << quote << (@scanner.scan_until(quote == '"' ? /"/n : /'/n) || raise(Malformed, 'unterminated attribute value'))
      end
    end
  end
end
