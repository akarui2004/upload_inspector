# frozen_string_literal: true

module UploadInspector
  # Allowlist inspection of OpenDocument text, spreadsheets and presentations (.odt/.ods/.odp).
  #
  # Rejected: Basic/script libraries and their manifest entries, encrypted parts, OLE objects
  # (binary "Object N" parts; embedded charts are XML sub-documents and are inspected like the
  # rest), event listeners, inline scripts, macro fields, program-running presentation actions,
  # applets/plugins/frames, DDE links, DTDs, DDE or file: formulas and any xlink:href leaving the
  # package other than http(s)/mailto hyperlinks.
  class OdfInspector
    include Rejectable
    include LinkCollector

    TYPES = %w[
      application/vnd.oasis.opendocument.text
      application/vnd.oasis.opendocument.spreadsheet
      application/vnd.oasis.opendocument.presentation
    ].freeze
    SEGMENT = '[A-Za-z0-9_\-. ]'
    ALLOWED_PARTS = [
      /\A(?:content|styles|meta|settings)\.xml\z/,
      %r{\AMETA-INF/manifest\.xml\z},
      /\Amanifest\.rdf\z/,
      %r{\APictures/#{SEGMENT}+\.(?:png|jpe?g|gif|svg|svm|wmf|emf|bmp|tiff?)\z}i,
      %r{\AThumbnails/thumbnail\.png\z},
      %r{\AObject \d+/(?:content|styles|meta|settings)\.xml\z},
      %r{\AObjectReplacements/Object \d+\z}, # preview image of an embedded object
      %r{\AConfigurations2/(?:#{SEGMENT}+/)*#{SEGMENT}+\.xml\z},
    ].freeze
    SCRIPT_PART = %r{\A(?:Basic|Scripts|Dialogs)/}i
    SCRIPT_MEDIA_TYPE = /basic|script|dialog/i
    OLE_MEDIA_TYPE = /oleobject/i
    XML_PART = /\.(?:xml|rdf|svg)\z/i
    HEAD_SIZE = 64
    # Local names; office:scripts is the (normally empty) container, office:script holds code.
    FORBIDDEN_ELEMENTS = %w[
      script execute-macro applet plugin floating-frame
      dde-source dde-connection-decl dde-connection-decls dde-link dde-links
    ].freeze
    RUNNING_ACTIONS = %w[execute verb].freeze # presentation:action values that run a program or OLE verb
    # DDE and web-fetching functions, and references into another document ('file:...'#$Sheet.A1).
    DANGEROUS_FORMULA = /\b(?:DDE|WEBSERVICE|FILTERXML)\s*\(|'[^']*'\s*#/i
    WEB_LINK = %r{\A(?:https?://|mailto:)}i
    LINK_WITH_SCHEME = /\A[A-Za-z][A-Za-z0-9+.\-]*:/n

    def initialize(policy, zip_inspector, links: [])
      @policy = policy
      @zip_inspector = zip_inspector
      @links = links
    end

    def verify!(entries, detected_type)
      check_mimetype!(entries.first, detected_type)
      # The manifest goes first: it says when the other parts are encrypted (and so unreadable).
      entries.drop(1).sort_by { |entry| entry.name == 'META-INF/manifest.xml' ? 0 : 1 }.each do |entry|
        next if entry.directory?

        check_part_name!(entry.name)
        if entry.name.match?(XML_PART)
          inspect_xml!(entry)
        elsif xml_like?(zip_inspector.read_head(entry, HEAD_SIZE))
          reject!(:odf_disguised_part, entry.name)
        end
      end
    end

  private

    attr_reader :policy, :zip_inspector

    # The first, stored member names the format; readers trust it over the extension.
    def check_mimetype!(entry, detected_type)
      reject!(:odf_malformed, 'mimetype is not the first member') unless entry&.name == 'mimetype'
      declared = zip_inspector.read_bounded(entry, HEAD_SIZE)
      reject!(:odf_malformed, "mimetype #{declared[0, 80].inspect}") unless declared == detected_type
    end

    def check_part_name!(name)
      reject!(:odf_macro, name) if name.match?(SCRIPT_PART)
      reject!(:odf_unknown_part, name) unless ALLOWED_PARTS.any? { |pattern| name.match?(pattern) }
    end

    def xml_like?(head)
      text = head.sub(/\A(?:\xEF\xBB\xBF|\xFF\xFE|\xFE\xFF)/n, '').delete("\0").lstrip
      text.start_with?('<')
    end

    def inspect_xml!(entry)
      name = entry.name
      xml = zip_inspector.read_bounded(entry, policy.max_inflate_size)
      reject!(:odf_unsupported_encoding, name) unless XmlScanner.supported_encoding?(xml)
      xml = xml.sub(SvgInspector::STANDARD_DOCTYPE, '') if name.match?(/\.svg\z/i)
      reject!(:odf_dtd, name) if xml.match?(XmlScanner::DTD)

      XmlScanner.new(xml).each do |kind, tag|
        check_element!(tag, name) if %i[open empty].include?(kind)
      end
    rescue XmlScanner::Malformed => e
      reject!(:odf_malformed, "#{name}: #{e.message}")
    end

    def check_element!(tag, name)
      local = tag.local_name
      reject!(:odf_active_content, "#{name}: <#{tag.name}>") if FORBIDDEN_ELEMENTS.include?(local)
      reject!(:office_encrypted, name) if local == 'encryption-data'

      # Pairs, not a hash: two prefixes may share a local name and both must be checked.
      attributes = XmlScanner.attributes(tag).map { |attribute, value| [attribute.split(':').last, value] }
      # Presentation listeners (next slide, open a link) carry an action; script listeners do not.
      if local == 'event-listener' && attributes.none? { |attribute, _| attribute == 'action' }
        reject!(:odf_active_content, "#{name}: <#{tag.name}>")
      end
      attributes.each { |attribute, value| check_attribute!(local, attribute, value, name) }
    end

    def check_attribute!(element, attribute, value, name)
      case attribute
      when 'href' then check_href!(element, value, name)
      when 'macro-name' then reject!(:odf_active_content, "#{name}: macro #{value[0, 80]}")
      when 'action' then reject!(:odf_active_content, "#{name}: #{value} action") if RUNNING_ACTIONS.include?(value)
      when 'formula' then reject!(:odf_dangerous_formula, "#{name}: #{value[0, 80]}") if value.match?(DANGEROUS_FORMULA)
      when 'full-path' then reject!(:odf_macro, "#{name}: #{value}") if value.match?(SCRIPT_PART)
      when 'media-type'
        reject!(:odf_macro, "#{name}: #{value}") if value.match?(SCRIPT_MEDIA_TYPE)
        reject!(:odf_embedded_object, "#{name}: #{value}") if value.match?(OLE_MEDIA_TYPE)
      end
    end

    # Hyperlinks (<text:a>, <draw:a>) may leave the package for the web; nothing else may.
    # Other targets must be relative paths that stay inside the package, read the way a lenient
    # resolver would: percent-decoded, backslashes as slashes, no ".." segment anywhere.
    def check_href!(element, target, name)
      target = target.gsub(/[\x00-\x20\x7F]/n, '')
      return add_link(target) if element == 'a' && target.match?(WEB_LINK)

      path = target.gsub(/%(\h\h)/n) { Regexp.last_match(1).hex.chr }.tr('\\', '/')
      escapes = path.match?(LINK_WITH_SCHEME) || path.start_with?('/') || path.split('/').include?('..')
      reject!(:odf_external_reference, "#{name}: #{target[0, 80]}") if escapes
    end
  end
end
