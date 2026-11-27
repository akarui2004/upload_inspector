# frozen_string_literal: true

require_relative 'integration_helper'
RACK = IntegrationHelper.load('rack', 'rack/mock_request')

class RackIntegrationTest < Minitest::Test
  include FixtureBuilder

  APP = ->(env) { [200, {}, ["ok #{Rack::Request.new(env).POST.keys.join(',')}"]] }

  def setup
    skip 'needs the rack gem (Gemfile group :integration)' unless RACK
    @app = UploadInspector::Rack.new(APP, paths: [%r{\A/uploads}], allowed_types: %w[text/plain], sandbox: false)
  end

  def post(path, params)
    env = Rack::MockRequest.env_for(path, method: 'POST', params:)
    status, headers, body = @app.call(env)
    [status, headers, body.join]
  end

  def upload(name, bytes) = Rack::Multipart::UploadedFile.new(write_file(name, bytes), 'text/plain')

  # A browser's <input type="file" name="doc[files][]" multiple> (MockRequest cannot build arrays of files).
  def post_files(field, files, type: 'multipart/form-data')
    parts = files.map do |name, bytes|
      "--XX\r\nContent-Disposition: form-data; name=\"#{field}\"; filename=\"#{name}\"\r\n" \
        "Content-Type: application/octet-stream\r\n\r\n#{bytes}\r\n"
    end
    input = "#{parts.join}--XX--\r\n".b
    env = Rack::MockRequest.env_for('/uploads', method: 'POST', input:, 'CONTENT_TYPE' => "#{type}; boundary=XX")
    status, headers, body = @app.call(env)
    [status, headers, body.join]
  end

  def test_unsafe_file_in_an_array_gets_422_json
    status, headers, body = post_files('doc[files][]', { 'a.txt' => 'hi', 'b.txt' => clean_pdf })
    assert_equal [422, 'application/json'], [status, headers['content-type']]
    assert_equal({ 'error' => 'is not an allowed file type', 'reason' => 'type_not_allowed',
                   'field' => 'doc[files][1]', }, JSON.parse(body))
  end

  def test_other_multipart_types_rack_parses_are_checked
    %w[multipart/mixed multipart/related].each do |type|
      assert_equal 422, post_files('doc', { 'b.txt' => clean_pdf }, type:).first, type
    end
  end

  def test_path_variants_a_router_accepts_are_checked
    app = UploadInspector::Rack.new(APP, paths: ['/uploads'], allowed_types: %w[text/plain], sandbox: false)
    ['/uploads', '//uploads', '/uploads/', '/%75ploads', '/uploads%2F'].each do |path|
      env = Rack::MockRequest.env_for('/', method: 'POST', params: { 'doc' => upload('b.txt', clean_pdf) })
      env['PATH_INFO'] = path
      assert_equal 422, app.call(env).first, path
    end
  end

  def test_unsafe_file_in_a_nested_hash
    status, _, body = post('/uploads', 'doc' => { 'file' => upload('b.txt', clean_pdf) })
    assert_equal [422, 'doc[file]'], [status, JSON.parse(body)['field']]
  end

  def test_safe_files_and_other_paths_pass_through
    assert_equal [200, 'ok doc,title'], post('/uploads/1', 'doc' => upload('a.txt', 'hi'), 'title' => 'x').values_at(0, 2)
    assert_equal 200, post('/other', 'doc' => upload('b.txt', clean_pdf)).first
    assert_raises(ArgumentError) { UploadInspector::Rack.new(APP, paths: []) }
  end
end
