# frozen_string_literal: true

require 'json'
require 'rack'

module UploadInspector
  # Rack middleware: checks every file in multipart requests to the given paths before the app
  # sees them, and answers 422 with JSON when one is unsafe. Works with any Rack app
  # (Rails, Sinatra, Hanami, Roda).
  #
  #   use UploadInspector::Rack, paths: [%r{\A/uploads}], allowed_types: UploadInspector::Presets::IMAGES
  #
  # The check runs inside the request (in the sandbox unless sandbox: false): limit +paths+ to
  # upload endpoints taking small files and check large ones in a background job.
  # Other keywords are UploadInspector.check keywords. The 422 body is
  # { "error": message, "reason": reason, "field": form field name }.
  class Rack
    def initialize(app, paths:, **check_options)
      raise ArgumentError, 'paths: must list the upload endpoints to check' if Array(paths).empty?

      @app = app
      @paths = Array(paths)
      @check_options = check_options
    end

    def call(env)
      request = ::Rack::Request.new(env)
      return @app.call(env) unless @paths.any? { |path| path === request.path_info }

      # Not gated on form_data?: Rack also parses multipart/mixed and multipart/related bodies
      # (parseable_data?) into the same params. POST is {} for bodies Rack does not parse.

      uploads(request.POST).each do |field, upload|
        result = UploadInspector.check(upload[:tempfile], filename: upload[:filename].to_s, **@check_options)
        return reject(field, result) unless result.safe?
      end
      @app.call(env) # the parsed form stays cached in env, the app does not parse it again
    end

    private

    # [field name, upload hash] for every file in the (nested) params.
    def uploads(params, prefix = nil)
      params.flat_map do |key, value|
        value = value.each_with_index.to_h { |item, index| [index, item] } if value.is_a?(Array)
        name = prefix ? "#{prefix}[#{key}]" : key.to_s
        next [] unless value.is_a?(Hash)
        next [[name, value]] if value[:tempfile]

        uploads(value, name)
      end
    end

    def reject(field, result)
      body = JSON.generate(error: result.message, reason: result.reason, field:)
      [422, { 'content-type' => 'application/json', 'content-length' => body.bytesize.to_s }, [body]]
    end
  end
end
