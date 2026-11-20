# frozen_string_literal: true

require 'strscan'

module UploadInspector
  # Finds event-handler attributes ("onclick=...") the way a browser's HTML tokenizer reads
  # tags (WHATWG tag, attribute and comment states), so quotes, "<" and ">" inside a tag cannot
  # hide one from a regex. One linear pass.
  #
  # Assumes no raw-text element (script, style, textarea, title, ...), whose content a
  # browser does not read as tags: TextInspector rejects those tags before this runs.
  module HtmlHandlerScanner
    # ASCII classes without /i: under Unicode case folding [a-z] also matches U+017F and U+212A,
    # which a browser reads as plain text, not as a tag start.
    HANDLER = /\A[oO][nN][A-Za-z]/ # attribute names are case-insensitive in HTML
    TAG_START = %r{<(?=[A-Za-z!?/])}

    module_function

    # Returns the first handler attribute name, or nil.
    def find(text)
      scanner = StringScanner.new(text)
      while scanner.skip_until(TAG_START) # "<" before anything else is text
        if scanner.skip(/!--/)
          # "<!-->" and "<!--->" end at once; otherwise "-->" or "--!>"; unterminated runs to the end.
          scanner.skip(/-?>/) || scanner.skip_until(/--!?>/) || break
        elsif scanner.skip(%r{/?[A-Za-z]}) # start or end tag
          scanner.skip(%r{[^\s/>]*})
          handler = attributes(scanner)
          return handler if handler

          scanner.skip(%r{[\s/]*>})
        elsif scanner.skip(%r{[!?/]}) # bogus comment
          scanner.skip_until(/>/) || break
        end
      end
      nil
    end

    # One attribute: separators, a name (may start with "=", holds quotes and "<" as plain
    # characters), then an optional "=" value, quoted or not.
    ATTRIBUTE = %r{[\s/]*([^\s/>][^\s/>=]*)\s*(?:=\s*(?:"[^"]*"?|'[^']*'?|[^\s>]*))?}

    # Reads attributes up to the ">" that ends the tag; returns the first handler name.
    def attributes(scanner)
      while scanner.skip(ATTRIBUTE)
        return scanner[1] if scanner[1].match?(HANDLER)
      end
      nil # at ">" (or the end): the tag is over
    end
  end
end
