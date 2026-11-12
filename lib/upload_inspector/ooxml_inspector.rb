# frozen_string_literal: true

module UploadInspector
  # Allowlist inspection of Office Open XML (docx / pptx / xlsx) parts.
  #
  # Every part name must match a known-safe pattern. XML parts are read (bounded) and
  # rejected for macro content types, DTDs, external relationships (remote template /
  # Follina-style OLE links), relationships to macro/OLE/ActiveX parts, Word field codes that
  # fetch or run things (DDE, INCLUDETEXT, DATABASE...), PowerPoint program/macro actions,
  # Excel DDE formulas and external data connections (ODBC, web queries, Power Query).
  # Patterns run on entity-decoded text, because Office decodes &#..; before acting on it.
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
    FORBIDDEN_PARTS = %r{vbaProject|vbaData|/embeddings/|/activeX/|/externalLinks/|oleObject|/macrosheets/|/dialogsheets/|
                         attachedToolbars|customUI|/connections\.xml\z|/queryTables/}xi
    # Relationship types that load code or objects even when the target part looks harmless.
    FORBIDDEN_RELATIONSHIP = /\A(?:vbaProject|wordVbaData|oleObject|package|activeXControl|activeXControlBinary|control|
                               attachedToolbars|aFChunk|keyMapCustomizations)\z/xi

    MACRO_CONTENT_TYPE = /macroEnabled|vbaProject|ms-office\.vba|activeX|oleObject/i
    DTD = /<!DOCTYPE|<!ENTITY/i
    PREFIX = '(?:[\w.\-]+:)?'
    ATTRIBUTES = %q{(?:[^>"']|"[^"]*"|'[^']*')*} # quote-aware: ">" inside a value does not end the tag
    RELATIONSHIP = /<#{PREFIX}Relationship\b(#{ATTRIBUTES})>/n
    ATTRIBUTE = /([\w:.\-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/n
    FLD_SIMPLE = /<#{PREFIX}fldSimple\b[^>]*?\b#{PREFIX}instr\s*=\s*(?:"([^"]*)"|'([^']*)')/mn
    DANGEROUS_FIELD = /(?<![A-Z])(?:DDE|DDEAUTO|INCLUDETEXT|INCLUDEPICTURE|INCLUDE|IMPORT|LINK|QUOTE|DATABASE|MACROBUTTON)(?![A-Z])/
    PPT_ACTION = %r{ppaction://(?:program|macro|ole)}i
    FORMULA_ELEMENTS = %w[f definedName formula formula1 formula2].freeze
    FORMULA_STRING = /"(?:[^"]|"")*"/n
    DATA_MASHUP = /DataMashup/ # Power Query package stored in a customXml part
    SAFE_EXTERNAL_TARGET = /\A(?:https?|mailto):/i
    XML_ENTITIES = { 'amp' => '&', 'lt' => '<', 'gt' => '>', 'quot' => '"', 'apos' => "'" }.freeze
    CDATA = /(<!\[CDATA\[.*?\]\]>)/mn

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
      decoded = decode_entities(xml)
      reject!(:ooxml_program_action, name) if decoded.match?(PPT_ACTION)

      if name == '[Content_Types].xml'
        reject!(:ooxml_macro_content_type, name) if decoded.match?(MACRO_CONTENT_TYPE)
      elsif name.end_with?('.rels')
        check_relationships!(xml, name)
      elsif name.start_with?('word/')
        check_word_fields!(xml, name)
      elsif name.start_with?('xl/')
        check_formulas!(xml, name)
      elsif name.start_with?('customXml/')
        reject!(:ooxml_external_data, "#{name}: Power Query") if decoded.match?(DATA_MASHUP)
      end
    end

    # External targets are only allowed for plain web/mail hyperlinks; macro/OLE/ActiveX
    # relationship types are rejected whatever their target.
    def check_relationships!(xml, name)
      xml.scan(RELATIONSHIP) do |(raw_attributes)|
        attributes = parse_attributes(raw_attributes)
        type = attributes['Type'].to_s
        kind = type.split('/').last.to_s
        target = attributes['Target'].to_s
        if attributes['TargetMode'].to_s.casecmp?('External') && !(kind == 'hyperlink' && target.match?(SAFE_EXTERNAL_TARGET))
          reject!(:ooxml_external_relationship, "#{name}: #{kind} -> #{target}")
        end
        reject!(:ooxml_forbidden_relationship, "#{name}: #{kind}") if kind.match?(FORBIDDEN_RELATIONSHIP)
      end
    end

    # Field instructions may be split across runs, so all pieces are joined before matching.
    def check_word_fields!(xml, name)
      pieces = element_texts(xml, 'instrText') + xml.scan(FLD_SIMPLE).flatten.compact.map { |piece| decode_entities(piece) }
      return if pieces.empty?

      match = pieces.join.upcase.match(DANGEROUS_FIELD)
      reject!(:ooxml_dangerous_field, "#{name}: #{match[0]}") if match
    end

    # DDE references look like app|topic!item; "|" only appears legitimately inside "strings".
    def check_formulas!(xml, name)
      FORMULA_ELEMENTS.each do |element|
        element_texts(xml, element).each do |formula|
          reject!(:ooxml_dde_formula, name) if formula.gsub(FORMULA_STRING, '').include?('|')
        end
      end
    end

    # Text content of every <prefix:element ...>...</prefix:element>, CDATA unwrapped and
    # entities decoded, i.e. what Office reads.
    def element_texts(xml, element)
      pattern = %r{<#{PREFIX}#{element}\b#{ATTRIBUTES}(?<!/)>(.*?)</#{PREFIX}#{element}\s*>}mn
      xml.scan(pattern).map do |(inner)|
        inner.split(CDATA).map do |part|
          part.start_with?('<![CDATA[') ? part.byteslice(9...-3) : decode_entities(part.gsub(/<[^>]*>/n, ''))
        end.join
      end
    end

    def parse_attributes(raw)
      raw.scan(ATTRIBUTE).to_h do |key, double_quoted, single_quoted|
        [key.split(':').last, decode_entities(double_quoted || single_quoted)]
      end
    end

    def decode_entities(text)
      text.to_s.b
          .gsub(/&#[xX](\h+);/n) { codepoint_bytes(Regexp.last_match(1).hex) }
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
