# frozen_string_literal: true

module UploadInspector
  # Allowlist inspection of Office Open XML (docx / pptx / xlsx) parts.
  #
  # Every part name must match a known-safe pattern. XML parts are read (bounded) and
  # rejected for macro content types, DTDs, external relationships (remote template /
  # Follina-style OLE links), Word field codes that fetch or run things (DDE, INCLUDETEXT...),
  # PowerPoint program/macro actions and Excel DDE formulas.
  class OoxmlInspector
    include Rejectable

    SEGMENT = '[A-Za-z0-9_\-.]'
    ALLOWED_PARTS = [
      %r{\A\[Content_Types\]\.xml\z},
      %r{\A(?:#{SEGMENT}+/)*_rels/#{SEGMENT}*\.rels\z},
      %r{\A(?:word|ppt|xl|customXml|docProps)/(?:#{SEGMENT}+/)*#{SEGMENT}+\.xml\z},
      %r{\A(?:word|ppt|xl)/media/#{SEGMENT}+\.(?:png|jpe?g|gif|bmp|tiff?|emf|wmf|svg|wdp|jxr)\z}i,
      %r{\AdocProps/thumbnail\.(?:jpe?g|png|emf|wmf)\z}i,
      %r{\A(?:word|ppt|xl)/fonts/#{SEGMENT}+\.(?:odttf|fntdata)\z}i,
      %r{\A(?:word|ppt|xl)/printerSettings/printerSettings\d+\.bin\z},
    ].freeze
    FORBIDDEN_PARTS = %r{vbaProject|vbaData|/embeddings/|/activeX/|/externalLinks/|oleObject|/macrosheets/|/dialogsheets/|attachedToolbars|customUI}i

    MACRO_CONTENT_TYPE = /macroEnabled|vbaProject|ms-office\.vba|activeX|oleObject/i
    DTD = /<!DOCTYPE|<!ENTITY/i
    PREFIX = '(?:[\w.\-]+:)?'
    RELATIONSHIP = /<#{PREFIX}Relationship\b([^>]*)>/n
    ATTRIBUTE = /([\w:.\-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/n
    INSTR_TEXT = %r{<#{PREFIX}instrText\b[^>]*>(.*?)</#{PREFIX}instrText>}mn
    FLD_SIMPLE = /<#{PREFIX}fldSimple\b[^>]*?\b#{PREFIX}instr\s*=\s*(?:"([^"]*)"|'([^']*)')/mn
    DANGEROUS_FIELD = /(?<![A-Z])(?:DDE|DDEAUTO|INCLUDETEXT|INCLUDEPICTURE|IMPORT|LINK|QUOTE)(?![A-Z])/
    PPT_ACTION = %r{ppaction://(?:program|macro|ole)}i
    DDE_FORMULA = /<#{PREFIX}f\b[^>]*>[^<]*\|/n
    SAFE_EXTERNAL_TARGET = /\A(?:https?|mailto):/i
    XML_ENTITIES = { 'amp' => '&', 'lt' => '<', 'gt' => '>', 'quot' => '"', 'apos' => "'" }.freeze

    def initialize(policy, zip_inspector)
      @policy = policy
      @zip_inspector = zip_inspector
    end

    def verify!(entries)
      reject!(:ooxml_missing_content_types) unless entries.any? { |e| e.name == '[Content_Types].xml' }

      entries.each do |entry|
        next if entry.directory?

        check_part_name!(entry.name)
        inspect_xml!(entry) if entry.name.end_with?('.xml', '.rels')
      end
    end

  private

    attr_reader :policy, :zip_inspector

    def check_part_name!(name)
      reject!(:ooxml_forbidden_part, name) if name.match?(FORBIDDEN_PARTS)
      reject!(:ooxml_unknown_part, name) unless ALLOWED_PARTS.any? { |pattern| name.match?(pattern) }
    end

    def inspect_xml!(entry)
      name = entry.name
      xml = zip_inspector.read_bounded(entry, policy.max_inflate_size)
      # Office writes UTF-8; other encodings would let patterns below be bypassed.
      reject!(:ooxml_unsupported_encoding, name) if xml.include?("\0") || xml.start_with?("\xFF\xFE".b, "\xFE\xFF".b)
      reject!(:ooxml_dtd, name) if xml.match?(DTD)
      reject!(:ooxml_program_action, name) if xml.match?(PPT_ACTION)

      if name == '[Content_Types].xml'
        reject!(:ooxml_macro_content_type, name) if xml.match?(MACRO_CONTENT_TYPE)
      elsif name.end_with?('.rels')
        check_relationships!(xml, name)
      elsif name.start_with?('word/')
        check_word_fields!(xml, name)
      elsif name.start_with?('xl/')
        reject!(:ooxml_dde_formula, name) if xml.match?(DDE_FORMULA)
      end
    end

    # External targets are only allowed for plain web/mail hyperlinks.
    def check_relationships!(xml, name)
      xml.scan(RELATIONSHIP) do |(raw_attributes)|
        attributes = parse_attributes(raw_attributes)
        next unless attributes['TargetMode'].to_s.casecmp?('External')

        type = attributes['Type'].to_s
        target = attributes['Target'].to_s
        next if type.end_with?('/hyperlink') && target.match?(SAFE_EXTERNAL_TARGET)

        reject!(:ooxml_external_relationship, "#{name}: #{type.split('/').last} -> #{target}")
      end
    end

    # Field instructions may be split across runs, so all pieces are joined before matching.
    def check_word_fields!(xml, name)
      pieces = xml.scan(INSTR_TEXT).flatten + xml.scan(FLD_SIMPLE).flatten.compact
      return if pieces.empty?

      instructions = pieces.map { |piece| decode_entities(piece) }.join.upcase
      match = instructions.match(DANGEROUS_FIELD)
      reject!(:ooxml_dangerous_field, "#{name}: #{match[0]}") if match
    end

    def parse_attributes(raw)
      raw.scan(ATTRIBUTE).to_h do |key, double_quoted, single_quoted|
        [key.split(':').last, decode_entities(double_quoted || single_quoted)]
      end
    end

    def decode_entities(text)
      text.to_s.b
          .gsub(/&#x(\h+);/n) { codepoint_bytes(Regexp.last_match(1).hex) }
          .gsub(/&#(\d+);/n) { codepoint_bytes(Regexp.last_match(1).to_i) }
          .gsub(/&(amp|lt|gt|quot|apos);/n) { XML_ENTITIES[Regexp.last_match(1)] }
    end

    # Invalid code points become a marker that never matches an allowed value (fail closed).
    def codepoint_bytes(codepoint)
      [codepoint].pack('U').b
    rescue RangeError
      "�".b
    end
  end
end
