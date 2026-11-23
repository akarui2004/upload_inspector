# frozen_string_literal: true

require 'fileutils'
require 'stringio'
require 'tmpdir'
require 'upload_inspector'

# Builds hostile and clean sample files on the fly, so no binary fixtures are committed.
module FixtureBuilder
  DOCX = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  PPTX = 'application/vnd.openxmlformats-officedocument.presentationml.presentation'

  CONTENT_TYPES = <<~XML
    <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
      <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
      <Default Extension="xml" ContentType="application/xml"/>
      <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
    </Types>
  XML
  ROOT_RELS = <<~XML
    <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
      <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
    </Relationships>
  XML

  def tmp_path(name)
    @tmpdir ||= Dir.mktmpdir('upload_inspector_test')
    File.join(@tmpdir, name)
  end

  def teardown
    FileUtils.remove_entry(@tmpdir) if @tmpdir
    super
  end

  def write_file(name, bytes)
    path = tmp_path(name)
    File.binwrite(path, bytes)
    path
  end

  def pdf_bytes(*objects, trailer: '')
    body = objects.each_with_index.map { |obj, i| "#{i + 1} 0 obj\n#{obj}\nendobj\n" }.join
    "%PDF-1.7\n%\xE2\xE3\xCF\xD3\n".b + body.b + "trailer\n<< /Root 1 0 R #{trailer}>>\n%%EOF\n".b
  end

  def clean_pdf
    pdf_bytes('<< /Type /Catalog /Pages 2 0 R >>', '<< /Type /Pages /Kids [] /Count 0 >>')
  end

  # Object stream whose compressed content is +inner+.
  def pdf_with_object_stream(inner, dictionary: '/Filter /FlateDecode')
    data = dictionary.include?('FlateDecode') ? Zlib::Deflate.deflate(inner) : inner
    stream = "<< /Type /ObjStm /N 1 /First 4 #{dictionary} /Length #{data.bytesize} >>\nstream\n".b +
             data.b + "\nendstream".b
    pdf_bytes('<< /Type /Catalog /Pages 2 0 R >>', '<< /Type /Pages /Kids [] /Count 0 >>', stream)
  end

  # String-keyed entries arrive as keywords when passed without braces.
  def zip_bytes(entries = {}, encrypter: nil, **more_entries)
    entries = entries.merge(more_entries.transform_keys(&:to_s))
    io = write_zip_buffer(encrypter) do |zip|
      entries.each do |name, content|
        zip.put_next_entry(name)
        zip.write(content)
      end
    end
    io.string
  end

  # rubyzip 3 takes encrypter as a keyword, rubyzip 2 positionally.
  def write_zip_buffer(encrypter, &)
    keyword = Zip::OutputStream.method(:write_buffer).parameters.include?(%i[key encrypter])
    if keyword
      Zip::OutputStream.write_buffer(StringIO.new(+''), encrypter:, &)
    else
      Zip::OutputStream.write_buffer(StringIO.new(+''), encrypter, &)
    end
  end

  def docx_bytes(document_xml: '<w:document xmlns:w="w"><w:body/></w:document>', extra: {}, document_rels: nil)
    entries = {
      '[Content_Types].xml' => CONTENT_TYPES,
      '_rels/.rels' => ROOT_RELS,
      'word/document.xml' => document_xml,
      'docProps/core.xml' => '<cp:coreProperties xmlns:cp="cp"/>',
    }
    entries['word/_rels/document.xml.rels'] = document_rels if document_rels
    zip_bytes(entries.merge(extra))
  end

  END_OF_CHAIN = 0xFFFFFFFE
  NO_STREAM = 0xFFFFFFFF

  # Minimal version 3 Compound File (legacy Office container) with +streams+ at the root:
  # { name => bytes } (nil makes an empty storage). Streams under 4096 bytes go to the mini
  # stream, as real writers do. +fat_patch+ ({ sector => value }) corrupts the FAT on purpose.
  def cfb_bytes(streams, fat_patch: {})
    sectors = []
    fat = []
    allocate = lambda do |data|
      return END_OF_CHAIN if data.empty?

      chunks = data.b.scan(/.{1,512}/mn)
      start = sectors.size
      chunks.each_with_index do |chunk, i|
        sectors << chunk.ljust(512, "\0")
        fat << (i == chunks.size - 1 ? END_OF_CHAIN : start + i + 1)
      end
      start
    end

    mini = +''.b
    mini_fat = []
    entries = streams.map do |name, data|
      next [name, 1, 0, 0] if data.nil?
      next [name, 2, allocate.call(data), data.bytesize] if data.bytesize >= 4096

      start = mini.bytesize / 64
      count = (data.bytesize / 64.0).ceil
      count.times { |i| mini_fat << (i == count - 1 ? END_OF_CHAIN : start + i + 1) }
      mini << data.b.ljust(count * 64, "\0")
      [name, 2, count.zero? ? END_OF_CHAIN : start, data.bytesize]
    end
    root = ['Root Entry', 5, allocate.call(mini), mini.bytesize]
    mini_fat_start = allocate.call(mini_fat.pack('V*'))
    directory = [root, *entries].each_with_index.map do |(name, type, start, size), index|
      sibling = index.positive? && index < entries.size ? index + 1 : NO_STREAM
      child = index.zero? && entries.any? ? 1 : NO_STREAM
      utf16 = "#{name}\0".encode('UTF-16LE').b
      [utf16, utf16.bytesize, type, 1, NO_STREAM, sibling, child, start, size, 0].pack('a64 v C C V V V @116 V V V')
    end.join
    directory << ([''.b, 0, 0, 0, NO_STREAM, NO_STREAM, NO_STREAM, 0, 0, 0].pack('a64 v C C V V V @116 V V V') * ((4 - (directory.bytesize / 128 % 4)) % 4))
    directory_start = allocate.call(directory)

    fat_count = ((sectors.size + 1) / 128.0).ceil
    fat_count += 1 while sectors.size + fat_count > fat_count * 128
    fat_ids = (sectors.size...(sectors.size + fat_count)).to_a
    fat.concat([0xFFFFFFFD] * fat_count)
    fat_patch.each { |sector, value| fat[sector] = value }
    fat.fill(NO_STREAM, fat.size...(fat_count * 128))
    sectors.concat(fat.pack('V*').scan(/.{512}/mn))

    header = [UploadInspector::CfbReader::MAGIC, ''.b, 0x3E, 3, 0xFFFE, 9, 6, ''.b, 0, fat_count, directory_start, 0, 4096,
              mini_fat_start, (mini_fat.size / 128.0).ceil, END_OF_CHAIN, 0, *fat_ids.first(109),
              *([NO_STREAM] * (109 - [fat_ids.size, 109].min)),].pack('a8 a16 v v v v v a6 V V V V V V V V V V109')
    header + sectors.join
  end

  # Word binary document: FIB start (flags at offset 10) followed by +text+.
  def word_document(text = 'Hello', flags: 0)
    [0xA5EC, 0xC1, 0, 0x409, 0, flags].pack('v6') + ("\0".b * 20) + text.b
  end

  # BIFF8 record: type, length, body.
  def biff(type, body = ''.b) = [type, body.bytesize].pack('vv') + body.b

  # Excel workbook globals with one sheet of +sheet_type+ (0 worksheet, 1 XLM macro sheet).
  def workbook(*records, sheet_type: 0)
    sheet = biff(0x0085, [0, 0, sheet_type, 6, 0].pack('V C C C C') + 'Sheet1')
    biff(0x0809, [0x0600, 0x0005, 0, 0, 0, 0].pack('v v v v V V')) + records.join + sheet + biff(0x000A)
  end

  # PowerPoint record; version 0xF marks a container.
  def ppt_record(type, body = ''.b, container: false)
    [container ? 0xF : 0, type, body.bytesize].pack('v v V') + body.b
  end

  ODT = 'application/vnd.oasis.opendocument.text'
  ODF_MANIFEST = <<~XML
    <?xml version="1.0" encoding="UTF-8"?>
    <manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.3">
      <manifest:file-entry manifest:full-path="/" manifest:media-type="%s"/>
      <manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/>
    </manifest:manifest>
  XML
  ODF_NAMESPACES = 'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" ' \
                   'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" ' \
                   'xmlns:xlink="http://www.w3.org/1999/xlink"'

  # OpenDocument package: "mimetype" first and stored, as readers require.
  def odf_bytes(body: '<text:p>Hello</text:p>', type: ODT, extra: {}, manifest: nil)
    content = %(<?xml version="1.0" encoding="UTF-8"?><office:document-content #{ODF_NAMESPACES}>) +
              %(<office:scripts/><office:body><office:text>#{body}</office:text></office:body></office:document-content>)
    io = write_zip_buffer(nil) do |zip|
      zip.put_next_entry('mimetype', nil, nil, Zip::Entry::STORED)
      zip.write(type)
      { 'content.xml' => content, 'META-INF/manifest.xml' => manifest || format(ODF_MANIFEST, type) }.merge(extra).each do |name, data|
        zip.put_next_entry(name)
        zip.write(data)
      end
    end
    io.string
  end

  def rels(*relationships)
    items = relationships.map { |attrs| "<Relationship #{attrs}/>" }.join
    %(<?xml version="1.0"?><Relationships xmlns="r">#{items}</Relationships>)
  end
end
