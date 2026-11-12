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

  def rels(*relationships)
    items = relationships.map { |attrs| "<Relationship #{attrs}/>" }.join
    %(<?xml version="1.0"?><Relationships xmlns="r">#{items}</Relationships>)
  end
end
