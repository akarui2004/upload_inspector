# frozen_string_literal: true

module UploadInspector
  # Client-supplied file names are attacker-controlled. Two jobs:
  #
  # - unsafe_reason: names that trick a person or a server, rejected by Inspector#verify!
  #   (bidi overrides showing "invoice‮fdp.exe" as "invoiceexe.pdf", control characters,
  #   a script extension hidden before the real one: "shell.php.jpg" runs as PHP on servers
  #   that map handlers by any extension, e.g. Apache mod_mime).
  # - sanitize: a name safe to store and serve, extension taken from the detected type.
  module Filename
    BIDI = /[‪-‮⁦-⁩]/
    CONTROL = /[\x00-\x1F\x7F]/
    # Extensions a server or OS may execute or render as active content. Only checked before
    # the last extension, so "my.report.v2.pdf" stays fine.
    EXECUTABLE = %w[
      exe scr com pif bat cmd msi msp dll cpl sys lnk reg jar vb vbs vbe js jse mjs wsf wsh hta ps1 psm1
      php php3 php4 php5 php7 phtml phar pht asp aspx ashx asmx cer jsp jspx cgi pl py rb sh
      html htm shtml xhtml svg svgz
    ].freeze
    WINDOWS_RESERVED = /\A(?:con|prn|aux|nul|com[0-9]|lpt[0-9])\z/i
    WINDOWS_INVALID = %r{[<>:"/\\|?*]}
    MAX_BYTES = 255

    module_function

    # Rejection reason detail, or nil when the name is acceptable.
    def unsafe_reason(name)
      name = name.to_s.dup.force_encoding(Encoding::UTF_8)
      return 'not valid UTF-8' unless name.valid_encoding?
      return 'bidirectional override character' if name.match?(BIDI)
      return 'control character' if name.match?(CONTROL)

      inner = File.basename(name.tr('\\', '/')).split('.')[1...-1].to_a
      hidden = inner.find { |ext| EXECUTABLE.include?(ext.strip.downcase) }
      "executable extension .#{hidden} before the last one" if hidden
    end

    # Name safe to store on any OS and serve: no path, no control/bidi/reserved characters,
    # no inner dots (so no hidden extensions), at most 255 bytes, and the extension of the
    # detected type (the client's spelling when it is one of that type's extensions).
    #
    #   Filename.sanitize('../../x.php.jpg', detected_type: 'image/jpeg') # => "x_php.jpg"
    def sanitize(name, detected_type:)
      base = File.basename(name.to_s.dup.force_encoding(Encoding::UTF_8).scrub('').tr('\\', '/'))
      client_ext = File.extname(base).delete_prefix('.').downcase
      exts = Marcel::TYPE_EXTS.fetch(detected_type.to_s, [])
      ext = exts.include?(client_ext) ? client_ext : exts.first
      stem = base.delete_suffix(File.extname(base)).gsub(Regexp.union(BIDI, CONTROL), '')
                 .gsub(WINDOWS_INVALID, '_').tr('.', '_').strip.sub(/[ _]+\z/, '')
      stem = 'file' if stem.empty?
      stem = "_#{stem}" if stem.match?(WINDOWS_RESERVED)
      suffix = ext ? ".#{ext}" : ''
      stem = stem.byteslice(0, MAX_BYTES - suffix.bytesize).scrub('') if stem.bytesize + suffix.bytesize > MAX_BYTES
      stem + suffix
    end
  end
end
