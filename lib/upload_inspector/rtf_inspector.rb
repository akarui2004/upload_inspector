# frozen_string_literal: true

require 'strscan'

module UploadInspector
  # Rejects RTF documents that embed objects or fetch/run things when opened.
  #
  # A real tokenizer (groups, control words, hex escapes, \bin data, \u with its fallback
  # characters) reads the file the way Word does, so whitespace, empty groups or escapes inside
  # data and field text change nothing. Rejected: any \obj* control word (OLE objects such as
  # Equation Editor exploits, links, OCX), \datastore, \*\template (remote template injection),
  # \dibitmap pictures and fields that fetch or run things (INCLUDEPICTURE, DDE, LINK...) or
  # link outside the web (HYPERLINK "file:..."). Groups must balance and nest at most MAX_DEPTH.
  class RtfInspector
    include Rejectable
    include LinkCollector

    TYPE = 'application/rtf'
    MAX_DEPTH = 256
    CONTROL_WORD = /\\([a-zA-Z]+)(-?\d+)? ?/n
    EMBEDDED_WORD = /\A(?:obj|datastore\z)/i
    WEB_LINK = %r{\A(?:https?://|mailto:)}i
    LINK_WITH_SCHEME = %r{\A(?:[A-Za-z][A-Za-z0-9+.\-]*:|\\\\|//)}n
    HYPERLINK = /\A\s*HYPERLINK\s+(\\l\b)?\s*"?([^"\s]*)/i

    def initialize(policy, links: [])
      @policy = policy
      @links = links
    end

    def verify!(path)
      reject!(:rtf_too_large, "exceeds #{policy.max_inflate_size} bytes") if File.size(path) > policy.max_inflate_size

      scan!(StringScanner.new(File.binread(path)))
    end

  private

    attr_reader :policy

    def scan!(scanner)
      @unicode_skip = [1] # \ucN per group: fallback characters after each \uN
      @skip = 0
      @field = nil # [group depth, instruction text] while inside \fldinst
      until scanner.eos?
        if scanner.skip(/\{/n) then open_group!
        elsif scanner.skip(/\}/n) then close_group!(scanner)
        elsif scanner.scan(CONTROL_WORD) then control_word!(scanner, scanner[1], scanner[2])
        elsif scanner.scan(/\\'(\h\h)/n) then text!(scanner[1].hex.chr)
        elsif scanner.scan(/\\([\\{}])/n) then text!(scanner[1])
        elsif scanner.skip(/\\./mn) then @skip = 0 # other control symbols (\*, \~, \-, ...)
        elsif scanner.skip(/\\\z/n) then reject!(:rtf_malformed, 'trailing backslash')
        else text!(scanner.scan(/[^\\{}]+/n).delete("\r\n"))
        end
      end
      reject!(:rtf_malformed, 'unclosed group') if @unicode_skip.size > 1
    end

    def open_group!
      @unicode_skip.push(@unicode_skip.last)
      reject!(:rtf_malformed, "groups nested deeper than #{MAX_DEPTH}") if @unicode_skip.size > MAX_DEPTH + 1
    end

    # Word stops reading at the end of the outermost group; anything but padding after it is refused.
    def close_group!(scanner)
      reject!(:rtf_malformed, 'unbalanced closing brace') if @unicode_skip.size == 1
      finish_field! if @field && @field[0] == @unicode_skip.size
      @unicode_skip.pop
      return unless @unicode_skip.size == 1

      reject!(:rtf_malformed, 'data after the document') unless scanner.rest.match?(/\A[\s\0]*\z/n)
      scanner.terminate
    end

    def control_word!(scanner, word, parameter)
      reject!(:rtf_embedded_object, "\\#{word}") if word.match?(EMBEDDED_WORD)
      case word
      when 'template' then reject!(:rtf_external_reference, '\\template')
      when 'dibitmap' then reject!(:rtf_risky_picture, '\\dibitmap')
      when 'fldinst' then @field ||= [@unicode_skip.size, +''.b]
      when 'uc' then @unicode_skip[-1] = parameter.to_i.clamp(0, 16)
      when 'u'
        text!([parameter.to_i % 65_536].pack('U').b)
        @skip = @unicode_skip.last
      when 'bin' then skip_binary!(scanner, parameter.to_i)
      end
    end

    # \binN is followed by N raw bytes that are data, not markup.
    def skip_binary!(scanner, length)
      reject!(:rtf_malformed, '\\bin length') if length.negative? || length > scanner.rest_size
      scanner.pos += length
    end

    # Characters right after \uN are fallbacks readers skip.
    def text!(text)
      if @skip.positive?
        dropped = [@skip, text.bytesize].min
        @skip -= dropped
        text = text.byteslice(dropped..)
      end
      @field[1] << text if @field
    end

    def finish_field!
      instruction = @field[1]
      @field = nil
      match = instruction.upcase.match(OoxmlInspector::DANGEROUS_FIELD)
      reject!(:rtf_dangerous_field, match[0]) if match

      link = instruction.match(HYPERLINK)
      return unless link && !link[1] # \l targets a bookmark in the document

      target = link[2]
      if target.match?(WEB_LINK) then add_link(target)
      elsif target.match?(LINK_WITH_SCHEME) then reject!(:rtf_external_reference, "HYPERLINK #{target[0, 80]}")
      end
    end
  end
end
