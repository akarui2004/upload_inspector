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
    HANDLER = /\Aon[a-z]/i

    module_function

    # Returns the first handler attribute name, or nil.
    def find(text)
      scanner = StringScanner.new(text)
      while scanner.skip_until(%r{<(?=[a-z!?/])}i) # "<" before anything else is text
        if scanner.skip(/!--/)
          # "<!-->" and "<!--->" end at once; otherwise "-->" or "--!>"; unterminated runs to the end.
          scanner.skip(/-?>/) || scanner.skip_until(/--!?>/) || break
        elsif scanner.skip(%r{/?[a-z]}i) # start or end tag
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
