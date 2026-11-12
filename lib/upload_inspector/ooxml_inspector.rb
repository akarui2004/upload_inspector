# frozen_string_literal: true

module UploadInspector
  # Allowlist inspection of Office Open XML (docx / pptx / xlsx) parts.
  #
  # Office decides what a part is from [Content_Types].xml and the relationship that points to
  # it, never from its path, so no check here trusts a path: every part is either inspected as
  # XML or proven not to be XML, every XML part gets every content check, and only
  # relationship types known to be passive are accepted. Rejected: macro/OLE/ActiveX parts and
  # content types, DTDs, external relationships (remote template / Follina-style OLE links),
  # Word field codes that fetch or run things (DDE, INCLUDETEXT, DATABASE...), PowerPoint
  # program/macro actions, Excel DDE formulas and external data (connections, query tables,
  # DDE/OLE links, Power Query). Patterns run on entity-decoded text, as Office reads it.
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
    XML_PART = /\.(?:xml|rels|svg)\z/i
    HEAD_SIZE = 64

    # Relationship types (last path segment) that only bind passive document parts. Anything
    # else (vbaProject, oleObject, package, control, aFChunk, connections, externalLink,
    # xlMacrosheet, webextension...) loads code, objects or external data and is rejected.
    ALLOWED_RELATIONSHIPS = /\A(?:
      officeDocument|core-properties|extended-properties|custom-properties|thumbnail|
      theme|themeOverride|image|hyperlink|font|hdphoto|printerSettings|customXml|customXmlProps|
      styles|stylesWithEffects|settings|webSettings|fontTable|numbering|footnotes|endnotes|header|footer|
      comments|commentsExtended|commentsIds|commentsExtensible|people|glossaryDocument|
      worksheet|chartsheet|sharedStrings|calcChain|table|tableSingleCells|pivotTable|pivotCacheDefinition|
      pivotCacheRecords|threadedComment|person|sheetMetadata|volatileDependencies|slicer|slicerCache|
      timeline|timelineCache|ctrlProp|xmlMaps|customProperty|namedSheetView|richValueRel|richStyles|
      rd[A-Za-z]+|FeaturePropertyBag|
      slide|slideLayout|slideMaster|notesSlide|notesMaster|handoutMaster|presProps|viewProps|tableStyles|
      commentAuthors|authors|tags|revisionInfo|changesInfo|
      chart|chartUserShapes|chartStyle|chartColorStyle|chartEx|drawing|
      diagramData|diagramLayout|diagramQuickStyle|diagramColors|diagramDrawing
    )\z/xi

    MACRO_CONTENT_TYPE = /macroEnabled|vbaProject|ms-office\.vba|activeX|oleObject/i
    FORBIDDEN_CONTENT_TYPE = /macrosheet|dialogsheet|spreadsheetml\.connections|queryTable|externalLink|
                              attachedToolbars|webextension|keyMapCustomizations/xi
    # Root or child elements of external-data and macro-sheet parts, whatever the part is called.
    FORBIDDEN_ELEMENTS = %w[ddeLink oleLink externalLink connections queryTable macrosheet dialogsheet].freeze
    DANGEROUS_FIELD = /(?<![A-Z])(?:DDE|DDEAUTO|INCLUDETEXT|INCLUDEPICTURE|INCLUDE|IMPORT|LINK|QUOTE|DATABASE|MACROBUTTON)(?![A-Z])/
    PPT_ACTION = %r{ppaction://(?:program|macro|ole)}i
    FORMULA_ELEMENTS = %w[f definedName formula formula1 formula2].freeze
    FORMULA_STRING = /"(?:[^"]|"")*"/n
    # "f" is also the OMML fraction element in Word, so formulas are only read in spreadsheet XML.
    SPREADSHEET_NAMESPACE = /spreadsheetml/i
    DATA_MASHUP = %r{<(?:[\w.\-]+:)?DataMashup\b|schemas\.microsoft\.com/DataMashup}i # Power Query package
    SAFE_EXTERNAL_TARGET = /\A(?:https?|mailto):/i

    def initialize(policy, zip_inspector)
      @policy = policy
      @zip_inspector = zip_inspector
    end

    def verify!(entries)
      reject!(:ooxml_missing_content_types) unless entries.any? { |e| e.name == '[Content_Types].xml' }

      entries.each do |entry|
        next if entry.directory?

        check_part_name!(entry.name)
        if entry.name.match?(XML_PART)
          inspect_xml!(entry)
        elsif xml_like?(zip_inspector.read_head(entry, HEAD_SIZE))
          # A content type override can make Office load "media/image1.png" as the main document.
          reject!(:ooxml_disguised_part, entry.name)
        end
      end
    end

  private

    attr_reader :policy, :zip_inspector

    def check_part_name!(name)
      reject!(:ooxml_forbidden_part, name) if name.match?(FORBIDDEN_PARTS)
      reject!(:ooxml_unknown_part, name) unless ALLOWED_PARTS.any? { |pattern| name.match?(pattern) }
    end

    # XML may start with a BOM and whitespace (UTF-16 adds NULs); binary media never does.
    def xml_like?(head)
      return false if head.empty?

      text = head.sub(/\A(?:\xEF\xBB\xBF|\xFF\xFE|\xFE\xFF)/n, '').delete("\0").lstrip
      text.empty? || text.start_with?('<')
    end

    def inspect_xml!(entry)
      name = entry.name
      xml = zip_inspector.read_bounded(entry, policy.max_inflate_size)
      reject!(:ooxml_unsupported_encoding, name) unless XmlScanner.supported_encoding?(xml)
      # SVG pictures commonly carry the standard W3C DOCTYPE (no entities); nothing else may.
      xml = xml.sub(SvgInspector::STANDARD_DOCTYPE, '') if name.match?(/\.svg\z/i)
      reject!(:ooxml_dtd, name) if xml.match?(XmlScanner::DTD)
      decoded = XmlScanner.decode_entities(xml)
      reject!(:ooxml_program_action, name) if decoded.match?(PPT_ACTION)
      reject!(:ooxml_external_data, "#{name}: Power Query") if decoded.match?(DATA_MASHUP)
      check_content_types!(decoded, name) if name == '[Content_Types].xml'

      scan_elements!(xml, name, spreadsheet: name.start_with?('xl/') || decoded.match?(SPREADSHEET_NAMESPACE))
    rescue XmlScanner::Malformed => e
      reject!(:ooxml_malformed_xml, "#{name}: #{e.message}")
    end

    def check_content_types!(decoded, name)
      reject!(:ooxml_macro_content_type, name) if decoded.match?(MACRO_CONTENT_TYPE)
      match = decoded.match(FORBIDDEN_CONTENT_TYPE)
      reject!(:ooxml_forbidden_content_type, match[0]) if match
    end

    # One pass over the tags. Field instructions may be split across runs, so all pieces are
    # joined before matching; formula text is collected per element.
    def scan_elements!(xml, name, spreadsheet:)
      relationships = name.end_with?('.rels')
      instructions = +''.b
      capture = nil # [element, text, nesting depth] while inside an instrText or formula element

      XmlScanner.new(xml).each do |kind, value|
        case kind
        when :text then capture[1] << XmlScanner.decode_entities(value) if capture
        when :cdata then capture[1] << value if capture
        when :open, :empty
          local = value.local_name
          reject!(:ooxml_forbidden_content, "#{name}: <#{local}>") if FORBIDDEN_ELEMENTS.include?(local)
          check_relationship!(value, name) if relationships && local == 'Relationship'
          instructions << field_instruction(value) if local == 'fldSimple'
          next unless kind == :open

          if capture.nil?
            capture = [local, +''.b, 1] if local == 'instrText' || FORMULA_ELEMENTS.include?(local)
          elsif local == capture[0]
            capture[2] += 1
          end
        when :close
          next unless capture && value.local_name == capture[0] && (capture[2] -= 1).zero?

          capture[0] == 'instrText' ? instructions << capture[1] : check_formula!(capture[1], name, spreadsheet)
          capture = nil
        end
      end

      match = instructions.upcase.match(DANGEROUS_FIELD)
      reject!(:ooxml_dangerous_field, "#{name}: #{match[0]}") if match
    end

    def field_instruction(tag)
      XmlScanner.attributes(tag).filter_map { |key, text| text if key.split(':').last == 'instr' }.join
    end

    # DDE references look like app|topic!item; "|" only appears legitimately inside "strings".
    def check_formula!(formula, name, spreadsheet)
      reject!(:ooxml_dde_formula, name) if spreadsheet && formula.gsub(FORMULA_STRING, '').include?('|')
    end

    # External targets are only allowed for plain web/mail hyperlinks, and every relationship
    # must be of a passive type whatever its target. OPC attributes are unqualified, so a
    # prefixed look-alike (x:TargetMode="Internal") is ignored, as Office ignores it.
    def check_relationship!(tag, name)
      attributes = XmlScanner.attributes(tag).to_h
      kind = attributes['Type'].to_s.split('/').last.to_s
      target = attributes['Target'].to_s
      external = attributes.key?('TargetMode') && !attributes['TargetMode'].casecmp?('Internal')
      if external && !(kind == 'hyperlink' && target.match?(SAFE_EXTERNAL_TARGET))
        reject!(:ooxml_external_relationship, "#{name}: #{kind} -> #{target}")
      end
      reject!(:ooxml_forbidden_relationship, "#{name}: #{kind}") unless kind.match?(ALLOWED_RELATIONSHIPS)
    end
  end
end
