# frozen_string_literal: true

require 'test_helper'

class UploadInspectorTest < Minitest::Test
  include FixtureBuilder

  OFFICE_AND_ZIP = ['application/pdf', 'application/zip', FixtureBuilder::DOCX, FixtureBuilder::PPTX].freeze

  def check(path, filename, sandbox: false, **options)
    UploadInspector.check(path, filename:, sandbox:, allowed_types: OFFICE_AND_ZIP, **options)
  end

  def assert_rejected(result, reason)
    refute result.safe?, "expected rejection #{reason}, got safe"
    assert_equal reason, result.reason, result.detail
  end

  # --- type and extension ---------------------------------------------------

  def test_accepts_clean_pdf
    result = check(write_file('a.pdf', clean_pdf), 'design.pdf')
    assert result.safe?, result.detail
    assert_equal 'application/pdf', result.detected_type
  end

  def test_rejects_executable_renamed_to_pdf
    path = write_file('a.pdf', "MZ\x90\x00".b + ("\x00".b * 200))
    assert_rejected check(path, 'design.pdf'), :type_not_allowed
  end

  # Text has no magic bytes, so Marcel falls back to the name (application/pdf); the structure
  # check must still reject it as not really a PDF.
  def test_rejects_plain_text_renamed_to_pdf
    assert_rejected check(write_file('a.pdf', 'just some text'), 'design.pdf'), :unverifiable_type
  end

  def test_rejects_pdf_with_mismatching_extension
    assert_rejected check(write_file('a.zip', clean_pdf), 'design.zip'), :extension_mismatch
  end

  def test_rejects_file_without_extension
    assert_rejected check(write_file('a', clean_pdf), 'design'), :extension_mismatch
  end

  def test_rejects_empty_and_oversized_files
    assert_rejected check(write_file('a.pdf', ''), 'a.pdf'), :empty_file
    assert_rejected check(write_file('b.pdf', clean_pdf), 'b.pdf', max_file_size: 10), :too_large
  end

  def test_rejects_unverifiable_type_unless_opted_in
    path = write_file('a.psd', "8BPS\x00\x01".b + ("\x00".b * 600))
    detected = Marcel::MimeType.for(Pathname(path), name: 'a.psd')
    assert_equal 'image/vnd.adobe.photoshop', detected
    assert_rejected check(path, 'a.psd', allowed_types: [detected]), :unverifiable_type
    assert check(path, 'a.psd', allow_unverifiable: [detected]).safe?
  end

  def test_unknown_policy_option_raises
    assert_raises(ArgumentError) { UploadInspector::Policy.new(nope: 1) }
  end

  def test_invalid_timeout_raises_at_policy_build
    [nil, 0, -1, '60'].each do |timeout|
      assert_raises(ArgumentError) { UploadInspector::Policy.new(timeout:) }
    end
  end

  # --- PDF -------------------------------------------------------------------

  def test_rejects_pdf_javascript
    path = write_file('a.pdf', pdf_bytes('<< /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>'))
    assert_rejected check(path, 'a.pdf'), :pdf_active_content
  end

  def test_rejects_hex_escaped_pdf_names
    path = write_file('a.pdf', pdf_bytes('<< /Type /Catalog /OpenAction << /S /J#61va#53cript >> >>'))
    result = check(path, 'a.pdf')
    assert_rejected result, :pdf_active_content
    assert_equal '/JavaScript', result.detail
  end

  def test_rejects_pdf_launch_and_embedded_files
    %w[/Launch /EmbeddedFiles /RichMedia /XFA /SubmitForm /GoToR].each do |name|
      path = write_file('a.pdf', pdf_bytes("<< /Type /Catalog /X << /S #{name} >> >>"))
      assert_rejected check(path, 'a.pdf'), :pdf_active_content
    end
  end

  def test_does_not_flag_names_that_only_share_a_prefix
    path = write_file('a.pdf', pdf_bytes('<< /Type /Catalog /JSON 1 /Launcher 2 >>'))
    assert check(path, 'a.pdf').safe?
  end

  def test_rejects_javascript_hidden_in_compressed_object_stream
    path = write_file('a.pdf', pdf_with_object_stream('3 0 << /S /JavaScript /JS (x) >>'))
    assert_rejected check(path, 'a.pdf'), :pdf_active_content
  end

  def test_accepts_clean_compressed_object_stream
    path = write_file('a.pdf', pdf_with_object_stream('3 0 << /Type /Page >>'))
    assert check(path, 'a.pdf').safe?
  end

  def test_rejects_object_stream_with_unsupported_filter
    path = write_file('a.pdf', pdf_with_object_stream('x', dictionary: '/Filter /LZWDecode'))
    assert_rejected check(path, 'a.pdf'), :pdf_unparsable
  end

  def test_rejects_corrupt_object_stream
    stream = "<< /Type /ObjStm /Filter /FlateDecode /Length 10 >>\nstream\nnotzlib!!!\nendstream"
    path = write_file('a.pdf', pdf_bytes('<< /Type /Catalog >>', stream))
    assert_rejected check(path, 'a.pdf'), :pdf_unparsable
  end

  def test_rejects_object_stream_inflate_bomb
    path = write_file('a.pdf', pdf_with_object_stream(' ' * 2_000_000))
    assert_rejected check(path, 'a.pdf', max_inflate_size: 1_000_000), :pdf_inflate_limit
  end

  def test_rejects_encrypted_pdf
    path = write_file('a.pdf', pdf_bytes('<< /Type /Catalog >>', trailer: '/Encrypt 3 0 R'))
    assert_rejected check(path, 'a.pdf'), :pdf_encrypted
  end

  def test_detects_token_across_chunk_boundary
    padding = 'x' * (UploadInspector::PdfInspector::CHUNK_SIZE - 40)
    path = write_file('a.pdf', pdf_bytes("<< /Type /Catalog /P (#{padding}) /AA << /S /JavaScript >> >>"))
    assert_rejected check(path, 'a.pdf'), :pdf_active_content
  end

  # --- OOXML -----------------------------------------------------------------

  def test_accepts_clean_docx
    result = check(write_file('a.docx', docx_bytes), 'a.docx')
    assert result.safe?, result.detail
  end

  def test_rejects_docx_with_vba_project
    path = write_file('a.docx', docx_bytes(extra: { 'word/vbaProject.bin' => 'x' }))
    assert_rejected check(path, 'a.docx'), :ooxml_forbidden_part
  end

  def test_rejects_docx_with_embedded_ole_object
    path = write_file('a.docx', docx_bytes(extra: { 'word/embeddings/oleObject1.bin' => 'x' }))
    assert_rejected check(path, 'a.docx'), :ooxml_forbidden_part
  end

  def test_rejects_unknown_part
    path = write_file('a.docx', docx_bytes(extra: { 'word/payload.bin' => 'MZ' }))
    assert_rejected check(path, 'a.docx'), :ooxml_unknown_part
  end

  def test_rejects_macro_content_type
    types = FixtureBuilder::CONTENT_TYPES.sub('</Types>',
                                              '<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>')
    path = write_file('a.docx', docx_bytes(extra: { '[Content_Types].xml' => types }))
    assert_rejected check(path, 'a.docx'), :ooxml_macro_content_type
  end

  def test_rejects_remote_template_injection
    relationships = rels('Id="r1" Type="http://x/relationships/attachedTemplate" Target="https://attacker.invalid/t.dotm" TargetMode="External"')
    path = write_file('a.docx', docx_bytes(document_rels: relationships))
    assert_rejected check(path, 'a.docx'), :ooxml_external_relationship
  end

  def test_rejects_external_mode_hidden_with_entities
    relationships = rels('Id="r1" Type="http://x/relationships/oleObject" Target="mhtml:https://attacker.invalid/!x" TargetMode="&#x45;xternal"')
    path = write_file('a.docx', docx_bytes(document_rels: relationships))
    assert_rejected check(path, 'a.docx'), :ooxml_external_relationship
  end

  def test_accepts_web_hyperlink_but_rejects_file_hyperlink
    web = rels('Id="r1" Type="http://x/relationships/hyperlink" Target="https://example.com" TargetMode="External"')
    assert check(write_file('a.docx', docx_bytes(document_rels: web)), 'a.docx').safe?

    local = rels('Id="r1" Type="http://x/relationships/hyperlink" Target="file://attacker.invalid/share/x.txt" TargetMode="External"')
    assert_rejected check(write_file('b.docx', docx_bytes(document_rels: local)), 'b.docx'), :ooxml_external_relationship
  end

  def test_rejects_dde_field_split_across_runs
    document = '<w:document xmlns:w="w"><w:body><w:p>' \
               '<w:r><w:instrText>DD</w:instrText></w:r><w:r><w:instrText>EAUTO placeholder</w:instrText></w:r>' \
               '</w:p></w:body></w:document>'
    path = write_file('a.docx', docx_bytes(document_xml: document))
    assert_rejected check(path, 'a.docx'), :ooxml_dangerous_field
  end

  def test_does_not_flag_hyperlink_field
    document = '<w:document xmlns:w="w"><w:body><w:fldSimple w:instr=" HYPERLINK &quot;https://example.com&quot; "/></w:body></w:document>'
    assert check(write_file('a.docx', docx_bytes(document_xml: document)), 'a.docx').safe?
  end

  def test_rejects_doctype
    path = write_file('a.docx', docx_bytes(document_xml: '<!DOCTYPE x [<!ENTITY e "x">]><w:document xmlns:w="w"/>'))
    assert_rejected check(path, 'a.docx'), :ooxml_dtd
  end

  def test_rejects_powerpoint_program_action
    document = '<w:document xmlns:w="w"><a:hlinkClick action="ppaction://program"/></w:document>'
    path = write_file('a.docx', docx_bytes(document_xml: document))
    assert_rejected check(path, 'a.docx'), :ooxml_program_action
  end

  def test_rejects_utf16_xml
    path = write_file('a.docx', docx_bytes(document_xml: "\xFF\xFE<\x00w\x00".b))
    assert_rejected check(path, 'a.docx'), :ooxml_unsupported_encoding
  end

  # --- generic zip -------------------------------------------------------------

  def test_accepts_zip_of_clean_pdfs
    path = write_file('a.zip', zip_bytes('one.pdf' => clean_pdf, 'dir/two.pdf' => clean_pdf))
    result = check(path, 'a.zip')
    assert result.safe?, result.detail
  end

  def test_rejects_zip_member_with_javascript
    bad = pdf_bytes('<< /Type /Catalog /OpenAction << /S /JavaScript >> >>')
    path = write_file('a.zip', zip_bytes('ok.pdf' => clean_pdf, 'bad.pdf' => bad))
    result = check(path, 'a.zip')
    assert_rejected result, :pdf_active_content
    assert_match 'bad.pdf', result.detail
  end

  def test_rejects_zip_member_executable
    path = write_file('a.zip', zip_bytes('setup.bin' => "MZ\x90\x00".b + ("\x00".b * 200)))
    assert_rejected check(path, 'a.zip'), :type_not_allowed
  end

  def test_rejects_nested_archive
    inner = zip_bytes('one.pdf' => clean_pdf)
    assert_rejected check(write_file('a.zip', zip_bytes('inner.zip' => inner)), 'a.zip'), :nested_archive
    assert_rejected check(write_file('b.zip', zip_bytes('inner.pdf' => inner)), 'b.zip'), :extension_mismatch
  end

  def test_rejects_path_traversal
    path = write_file('a.zip', zip_bytes('../evil.pdf' => clean_pdf))
    assert_rejected check(path, 'a.zip'), :zip_unsafe_path
  end

  def test_rejects_zip_bomb_ratio
    path = write_file('a.zip', zip_bytes('big.pdf' => "%PDF-1.7\n#{' ' * 20_000_000}"))
    assert_rejected check(path, 'a.zip'), :zip_bomb
  end

  def test_rejects_encrypted_entry
    encrypter = Zip::TraditionalEncrypter.new('secret')
    path = write_file('a.zip', zip_bytes({ 'a.pdf' => clean_pdf }, encrypter:))
    assert_rejected check(path, 'a.zip'), :zip_encrypted_entry
  end

  def test_rejects_corrupt_zip
    path = write_file('a.zip', "PK\x03\x04".b + ('garbage' * 50))
    refute check(path, 'a.zip').safe?
  end

  # --- sandbox -----------------------------------------------------------------

  def test_sandbox_returns_same_verdicts
    assert check(write_file('a.pdf', clean_pdf), 'a.pdf', sandbox: true).safe?

    bad = write_file('b.pdf', pdf_bytes('<< /OpenAction << /S /JavaScript >> >>'))
    result = check(bad, 'b.pdf', sandbox: true)
    assert_rejected result, :pdf_active_content
    assert_equal 'application/pdf', result.detected_type
  end

  # --- links -------------------------------------------------------------------

  def link_pdf(*uris)
    pdf_bytes(*uris.map { |uri| "<< /Type /Annot /Subtype /Link /A << /S /URI /URI (#{uri}) >> >>" })
  end

  def test_links_survive_the_sandbox
    path = write_file('a.pdf', link_pdf('https://example.com/a', 'mailto:x@example.com', 'https://example.com/a'))
    result = check(path, 'a.pdf', sandbox: true)
    assert result.safe?, result.detail
    assert_equal ['https://example.com/a', 'mailto:x@example.com'], result.links
  end

  def test_links_are_kept_on_rejection_and_in_report_mode
    path = write_file('a.pdf', pdf_bytes('<< /OpenAction << /S /URI /URI (https://example.com/x) >> >>'))
    assert_equal ['https://example.com/x'], check(path, 'a.pdf', sandbox: true, mode: :report).links
  end

  def test_links_are_capped
    path = write_file('a.pdf', link_pdf(*(1..150).map { |i| "https://example.com/#{i}" }))
    assert_equal UploadInspector::LinkCollector::MAX_LINKS, check(path, 'a.pdf').links.size
  end

  def test_links_from_docx_svg_and_zip_members
    docx = docx_bytes(document_rels: rels('Id="r1" Type="x/hyperlink" Target="https://example.com/d" TargetMode="External"'))
    assert_equal ['https://example.com/d'], check(write_file('a.docx', docx), 'a.docx').links

    svg = '<svg xmlns="http://www.w3.org/2000/svg"><a href="https://example.com/s"><text>x</text></a></svg>'
    assert_equal ['https://example.com/s'], check(write_file('a.svg', svg), 'a.svg', allowed_types: ['image/svg+xml']).links

    zip = zip_bytes('a.pdf' => link_pdf('https://example.com/1'), 'b.pdf' => link_pdf('https://example.com/2'))
    assert_equal %w[https://example.com/1 https://example.com/2], check(write_file('a.zip', zip), 'a.zip').links
  end

  def test_pdf_links_policy_is_validated
    assert_raises(ArgumentError) { UploadInspector::Policy.new(pdf_links: :maybe) }
    assert_equal :reject, UploadInspector::Policy.new(pdf_links: 'reject').pdf_links
    assert_rejected check(write_file('a.pdf', link_pdf('https://example.com')), 'a.pdf', sandbox: true, pdf_links: :reject), :pdf_link
  end

  def test_legacy_office_and_rtf_have_messages
    assert_equal 'must be saved as .docx, .xlsx or .pptx', UploadInspector::Result.reject(:legacy_office).message
    assert_equal 'is password-protected', UploadInspector::Result.reject(:office_encrypted).message
  end

  def test_sandbox_rejects_when_memory_limit_is_hit
    skip 'RLIMIT_DATA is only enforced on Linux' unless UploadInspector::Sandbox::MEMORY_LIMIT_SUPPORTED

    path = write_file('a.pdf', clean_pdf)
    refute check(path, 'a.pdf', sandbox: true, memory_limit: 5 * UploadInspector::MEGABYTE).safe?
  end

  def test_sandbox_rejects_on_timeout
    path = write_file('a.pdf', clean_pdf)
    assert_rejected check(path, 'a.pdf', sandbox: true, timeout: 0.001), :timeout
  end

  # A killed child cannot clean up, so its temp directory belongs to the parent.
  def test_sandbox_leaves_no_temp_directory_behind
    path = write_file('a.zip', zip_bytes('a.pdf' => clean_pdf))
    work_dirs = -> { Dir.children(Dir.tmpdir).grep(/\Aupload_inspector\d/) }
    before = work_dirs.call
    assert check(path, 'a.zip', sandbox: true).safe?
    assert_rejected check(path, 'a.zip', sandbox: true, timeout: 0.001), :timeout
    assert_equal before, work_dirs.call
  end

  # --- report mode, file names, serving ---------------------------------------

  def test_report_mode_accepts_but_keeps_the_reason
    path = write_file('a.zip', clean_pdf)
    result = check(path, 'a.zip', mode: :report)
    assert result.safe?
    assert_nil result.reason
    assert_equal :extension_mismatch, result.would_reject
    assert_nil check(write_file('b.pdf', clean_pdf), 'b.pdf', mode: :report).would_reject
    assert_equal :extension_mismatch, check(path, 'a.zip', mode: :report, sandbox: true).would_reject
    assert_raises(ArgumentError) { check(path, 'a.zip', mode: :warn) }
  end

  def test_hostile_names_are_rejected_not_raised
    path = write_file('a.pdf', clean_pdf)
    ["a\0.pdf", (+"a\xFF.pdf").force_encoding('UTF-8'), (+"a\xFF.pdf").b].each do |name|
      assert_rejected check(path, name, sandbox: true), :filename_unsafe
    end
  end

  def test_safe_filename
    jpeg = 'image/jpeg'
    assert_equal 'x_php.jpg', UploadInspector.safe_filename('../../x.php.jpg', detected_type: jpeg)
    assert_equal 'photo.jpeg', UploadInspector.safe_filename('C:\\Users\\a\\photo.JPEG', detected_type: jpeg)
    assert_equal 'invoicefdp.pdf', UploadInspector.safe_filename("invoice\u202Efdp.exe", detected_type: 'application/pdf')
    assert_equal '_CON.txt', UploadInspector.safe_filename('CON.txt', detected_type: 'text/plain')
    assert_equal 'file.pdf', UploadInspector.safe_filename('...', detected_type: 'application/pdf')
    assert_equal 'a_b.pdf', UploadInspector.safe_filename('a<b>?.pdf', detected_type: 'application/pdf')
    long = UploadInspector.safe_filename("#{'é' * 300}.pdf", detected_type: 'application/pdf')
    assert_operator long.bytesize, :<=, 255
    assert long.valid_encoding?
    assert long.end_with?('.pdf')
  end

  def test_safe_headers
    safe = UploadInspector::Result.accept('image/png')
    headers = UploadInspector.safe_headers(safe, filename: 'ảnh "1".png', inline: true)
    assert_equal 'image/png', headers['Content-Type']
    assert_equal %(inline; filename="_nh _1.png"; filename*=UTF-8''%E1%BA%A3nh%20_1.png), headers['Content-Disposition']
    assert_equal 'nosniff', headers['X-Content-Type-Options']
    assert_includes headers['Content-Security-Policy'], 'sandbox'

    svg = UploadInspector.safe_headers(UploadInspector::Result.accept('image/svg+xml'), inline: true)
    assert_equal 'attachment', svg['Content-Disposition']
    assert_equal 'text/csv; charset=utf-8', UploadInspector.safe_headers(UploadInspector::Result.accept('text/csv'))['Content-Type']
    assert_equal 'application/octet-stream', UploadInspector.safe_headers(UploadInspector::Result.reject(:x))['Content-Type']
  end

  def test_presets_are_verified_types
    all = UploadInspector::Presets.constants.flat_map { UploadInspector::Presets.const_get(_1) }
    path = write_file('a.txt', 'hello')
    assert check(path, 'a.txt', allowed_types: UploadInspector::Presets::TEXT).safe?
    assert all.all?(&:frozen?)
  end

  # VT is not HTML whitespace: it stays inside the unquoted value, so the quote that follows
  # is literal and the next tag is real.
  def test_handler_scanner_uses_html_whitespace
    scan = UploadInspector::HtmlHandlerScanner
    assert_equal 'onclick', scan.find("<x a=b\v\"> <y onclick=1>")
    assert_equal 'onclick', scan.find("<x\fonclick=1>")
    assert_nil scan.find("<x a=\"\v onclick=1\">")
  end
end
