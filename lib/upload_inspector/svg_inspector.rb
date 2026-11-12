# frozen_string_literal: true

module UploadInspector
  # Accepts only static SVG: no way to run script and no reference outside the file.
  #
  # Script can enter an SVG through script elements, event-handler attributes, javascript:
  # links (also set by animation), foreign-namespace content (XHTML/MathML), stylesheet
  # processing instructions (XSLT) and DTD entities; each of those is rejected. References
  # (href, src, CSS url()) may only point inside the document, to an embedded raster image, or,
  # for <a>, to a web/mail address, so opening the file never fetches anything.
  class SvgInspector
    include Rejectable

    TYPE = 'image/svg+xml'
    # The W3C public identifier without an internal subset declares no entities.
    STANDARD_DOCTYPE =
      %r{<!DOCTYPE\s+svg\s+PUBLIC\s+"-//W3C//DTD SVG 1\.[01](?: Tiny| Basic)?//EN"\s+"http://www\.w3\.org/[^"\[\]<>]*"\s*>}n
    FORBIDDEN_ELEMENTS = %w[script foreignobject iframe embed object handler listener].freeze
    FOREIGN_NAMESPACE = %r{1999/xhtml|1998/Math/MathML}i
    REFERENCE_ATTRIBUTES = %w[href src].freeze
    CSS_ATTRIBUTES = %w[style fill stroke filter mask clip-path marker marker-start marker-mid marker-end cursor].freeze
    EMBEDDED_IMAGE = %r{\Adata:image/(?:png|jpe?g|gif|webp);base64,[A-Za-z0-9+/=]*\z}i
    WEB_LINK = %r{\A(?:https?://|mailto:)}i
    SCRIPT_SCHEME = /\A(?:javascript|vbscript|data):/i
    ANIMATED_SCRIPT_TARGET = /href\z|\Aon/i
    IGNORED_IN_URL = /[\x00-\x20\x7F]/n # browsers drop these inside URLs and keywords
    CSS_SCRIPT = /@import|expression\(|javascript:|behavior:|-moz-binding/
    CSS_EXTERNAL = /url\((?!["']?#)|image-set\(|(?<![a-z-])(?:image|src)\(|cross-fade\(/

    def initialize(policy)
      @policy = policy
    end

    def verify!(path)
      reject!(:svg_too_large, "exceeds #{policy.max_inflate_size} bytes") if File.size(path) > policy.max_inflate_size

      xml = File.binread(path)
      reject!(:svg_unsupported_encoding) unless XmlScanner.supported_encoding?(xml)
      xml = xml.sub(STANDARD_DOCTYPE, '')
      reject!(:svg_dtd) if xml.match?(XmlScanner::DTD)
      scan!(xml)
    rescue XmlScanner::Malformed => e
      reject!(:svg_unparsable, e.message)
    end

  private

    attr_reader :policy

    def scan!(xml)
      root_seen = false
      style = nil # text of the <style> element being read
      XmlScanner.new(xml).each do |kind, value|
        case kind
        when :pi
          # <?xml-stylesheet?> loads external CSS or runs XSLT.
          reject!(:svg_active_content, 'processing instruction') unless value.match?(/\Axml(?:\s|\z)/n)
        when :text then style << XmlScanner.decode_entities(value) if style
        when :cdata then style << value if style
        when :open, :empty
          element = value.local_name.downcase
          reject!(:svg_unparsable, "root element is <#{element}>") unless root_seen || element == 'svg'
          root_seen = true
          reject!(:svg_active_content, "<#{element}>") if FORBIDDEN_ELEMENTS.include?(element)
          XmlScanner.attributes(value).each { |name, text| check_attribute!(element, name.downcase, text) }
          style = +''.b if kind == :open && element == 'style'
        when :close
          next unless style && value.local_name.casecmp?('style')

          check_css!(style)
          style = nil
        end
      end
      reject!(:svg_unparsable, 'no svg element') unless root_seen
    end

    def check_attribute!(element, name, value)
      local = name.split(':').last.to_s
      compact = value.gsub(IGNORED_IN_URL, '')
      if name == 'xmlns' || name.start_with?('xmlns:')
        reject!(:svg_active_content, 'XHTML or MathML content') if value.match?(FOREIGN_NAMESPACE)
      elsif local.start_with?('on')
        reject!(:svg_active_content, "#{name} event handler")
      elsif local == 'base'
        reject!(:svg_external_reference, name) # xml:base re-targets every relative reference
      elsif REFERENCE_ATTRIBUTES.include?(local)
        check_reference!(element, compact)
      elsif local == 'attributename'
        reject!(:svg_active_content, "animation of #{compact}") if compact.match?(ANIMATED_SCRIPT_TARGET)
      elsif CSS_ATTRIBUTES.include?(local) || compact.match?(/url\(/i)
        check_css!(value)
      end
    end

    def check_reference!(element, target)
      return if target.start_with?('#') || target.match?(EMBEDDED_IMAGE)
      return if element == 'a' && target.match?(WEB_LINK)

      reject!(:svg_active_content, "#{target[0, 40]} link") if target.match?(SCRIPT_SCHEME)
      reject!(:svg_external_reference, target[0, 80])
    end

    # CSS escapes can spell url( or @import in ways no pattern sees, so a backslash is refused.
    def check_css!(css)
      text = css.b.downcase.gsub(IGNORED_IN_URL, '')
      reject!(:svg_active_content, 'CSS escape or script') if text.include?('\\') || text.match?(CSS_SCRIPT)
      reject!(:svg_external_reference, 'CSS reference outside the document') if text.match?(CSS_EXTERNAL)
    end
  end
end
