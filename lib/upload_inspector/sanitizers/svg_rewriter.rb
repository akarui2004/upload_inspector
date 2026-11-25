# frozen_string_literal: true

require 'set'

module UploadInspector
  module Sanitizers
    # Rebuilds an SVG that passed the check from XmlScanner tokens, keeping only allowlisted
    # elements (static drawing, text, paint servers, filters, SMIL animation) and attributes.
    # Comments, processing instructions, the DOCTYPE, <metadata> and anything unknown are
    # dropped (an element with everything inside it); text and attribute values are decoded
    # and escaped again, so entities and CDATA come out in one canonical form. The output is
    # UTF-8, with only the SVG and XLink namespaces declared on the root.
    class SvgRewriter
      SVG_NAMESPACE = 'http://www.w3.org/2000/svg'
      XLINK_NAMESPACE = 'http://www.w3.org/1999/xlink'
      ELEMENTS = Set.new(%w[
        svg g defs symbol use title desc switch a style image
        path rect circle ellipse line polyline polygon text tspan textPath
        linearGradient radialGradient stop pattern clipPath mask marker
        filter feBlend feColorMatrix feComponentTransfer feComposite feConvolveMatrix feDiffuseLighting
        feDisplacementMap feDistantLight feDropShadow feFlood feFuncA feFuncB feFuncG feFuncR
        feGaussianBlur feImage feMerge feMergeNode feMorphology feOffset fePointLight
        feSpecularLighting feSpotLight feTile feTurbulence
        animate animateMotion animateTransform set mpath
      ]).freeze
      ANIMATIONS = Set.new(%w[animate animateMotion animateTransform set]).freeze
      ATTRIBUTES = Set.new(%w[
        id class style lang xml:space xml:lang href xlink:href target type media
        x y x1 y1 x2 y2 cx cy r rx ry fx fy fr width height d points pathLength viewBox
        preserveAspectRatio transform dx dy rotate textLength lengthAdjust startOffset method spacing side
        gradientUnits gradientTransform spreadMethod offset stop-color stop-opacity
        patternUnits patternContentUnits patternTransform clipPathUnits maskUnits maskContentUnits
        markerWidth markerHeight markerUnits refX refY orient
        fill fill-opacity fill-rule stroke stroke-width stroke-linecap stroke-linejoin stroke-miterlimit
        stroke-dasharray stroke-dashoffset stroke-opacity opacity color display visibility overflow clip
        clip-path clip-rule mask marker-start marker-mid marker-end filter
        font-family font-size font-style font-weight font-variant font-stretch text-anchor
        dominant-baseline alignment-baseline baseline-shift letter-spacing word-spacing
        text-decoration writing-mode direction unicode-bidi color-interpolation
        color-interpolation-filters shape-rendering text-rendering image-rendering paint-order
        vector-effect flood-color flood-opacity lighting-color transform-origin mix-blend-mode isolation
        filterUnits primitiveUnits in in2 result stdDeviation mode values operator k1 k2 k3 k4 order
        kernelMatrix divisor bias targetX targetY edgeMode kernelUnitLength preserveAlpha surfaceScale
        diffuseConstant specularConstant specularExponent azimuth elevation pointsAtX pointsAtY
        pointsAtZ limitingConeAngle z scale xChannelSelector yChannelSelector radius baseFrequency
        numOctaves seed stitchTiles tableValues slope intercept amplitude exponent
        attributeName attributeType begin dur end min max restart repeatCount repeatDur calcMode
        keyTimes keySplines from to by additive accumulate path keyPoints
      ]).freeze
      # Animation may only change attributes kept above, and never what a reference or CSS reads.
      ANIMATABLE = (ATTRIBUTES - %w[id class style href xlink:href attributeName]).freeze
      ESCAPES = { '&' => '&amp;', '<' => '&lt;', '>' => '&gt;', '"' => '&quot;',
                  "\t" => '&#9;', "\n" => '&#10;', "\r" => '&#13;', }.freeze
      TEXT_SPECIAL = /[&<>]/n
      ATTRIBUTE_SPECIAL = /[&<>"\t\n\r]/n # escaped whitespace survives attribute value normalization
      UTF8_BOM = "\xEF\xBB\xBF".b

      # Writes the rebuilt SVG of +path+ to +output+.
      def rewrite(path, output)
        out = +%(<?xml version="1.0" encoding="UTF-8"?>\n).b
        dropped = 0 # depth inside a dropped element
        depth = 0 # depth inside the root element
        root = true
        XmlScanner.new(utf8(File.binread(path))).each do |kind, value|
          if dropped.positive?
            dropped += 1 if kind == :open
            dropped -= 1 if kind == :close
            next
          end

          case kind
          when :open, :empty
            unless kept?(value)
              dropped = 1 if kind == :open
              next
            end

            out << start_tag(value, root:, empty: kind == :empty)
            root = false
            depth += 1 if kind == :open
          when :close
            out << "</#{value.name}>"
            depth -= 1
          when :text then out << escape(XmlScanner.decode_entities(value), TEXT_SPECIAL) if depth.positive?
          when :cdata then out << escape(value, TEXT_SPECIAL) if depth.positive?
          end
        end
        File.binwrite(output, out)
      end

    private

      # Single-byte declared encodings become UTF-8; the declaration itself is dropped as a PI.
      def utf8(xml)
        xml = xml.delete_prefix(UTF8_BOM)
        declared = xml[XmlScanner::DECLARED_ENCODING, 1]
        xml = xml.force_encoding(Encoding::ISO_8859_1).encode(Encoding::UTF_8) if declared && !declared.casecmp?('UTF-8')
        xml.b.sub(SvgInspector::STANDARD_DOCTYPE, '')
      end

      def kept?(tag)
        name = tag.name
        return false unless ELEMENTS.include?(name)
        return true unless ANIMATIONS.include?(name)

        target = XmlScanner.attributes(tag).find { |attribute, _| attribute == 'attributeName' }&.last
        name == 'animateMotion' || ANIMATABLE.include?(target)
      end

      def start_tag(tag, root:, empty:)
        out = +"<#{tag.name}".b
        out << %( xmlns="#{SVG_NAMESPACE}" xmlns:xlink="#{XLINK_NAMESPACE}") if root
        XmlScanner.attributes(tag).each do |name, value|
          out << %( #{name}="#{escape(value, ATTRIBUTE_SPECIAL)}") if ATTRIBUTES.include?(name)
        end
        out << (empty ? '/>' : '>')
      end

      def escape(text, special) = text.b.gsub(special, ESCAPES)
    end
  end
end
