# frozen_string_literal: true

module UploadInspector
  module Sanitizers
    # Text that passed the check is copied as is. With neutralize_csv_formulas, every CSV/TSV
    # cell the check would refuse as a formula (one calling a function or another program) gets
    # a leading single quote, so a spreadsheet shows it as text (OWASP CSV injection advice).
    # Cells are found with the check's own pattern, which over-approximates: a quote may also
    # land after a delimiter inside quoted text, exactly where the check would have objected.
    class TextRewriter
      def initialize(neutralize_csv_formulas: false)
        @neutralize = neutralize_csv_formulas
      end

      # Writes the text of +path+ (detected +type+) to +output+.
      def rewrite(path, type, output)
        return FileUtils.cp(path, output) unless @neutralize && TextInspector::SPREADSHEET_TYPES.include?(type)

        text = File.binread(path).force_encoding(Encoding::UTF_8) # valid UTF-8: the check ran first
        # Quoting a quoted cell exposes the cells the pattern skipped inside it; repeat until stable.
        loop do
          neutralized = neutralize(text)
          break if neutralized == text

          text = neutralized
        end
        File.binwrite(output, text)
      end

    private

      def neutralize(text)
        text.gsub(TextInspector::FORMULA_CELL) do
          match = Regexp.last_match
          cell = match[1] || match[2]
          next match[0] unless cell.match?(TextInspector::FORMULA_ACTION)

          match[0].dup.insert((match.begin(1) || match.begin(2)) - match.begin(0), "'")
        end
      end
    end
  end
end
