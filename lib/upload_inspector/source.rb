# frozen_string_literal: true

require 'tempfile'

module UploadInspector
  # Turns whatever an app holds for an upload into a local path plus the client-supplied name.
  #
  # Accepted sources (duck-typed, no Rails dependency):
  # - a path String or Pathname
  # - File / Tempfile / anything with +to_path+
  # - Rails ActionDispatch::Http::UploadedFile, Rack::Test::UploadedFile (+original_filename+ + path)
  # - ActiveStorage::Blob / ActiveStorage::Attached::One (+open+ yields a local copy, +filename+)
  # - any readable IO (StringIO, ...), copied to a temp file, at most max_file_size + 1 bytes
  module Source
    module_function

    # Yields (path, filename). +filename+ overrides the name taken from the source; it is
    # required when the source carries none (a path or File only knows its on-disk name,
    # e.g. RackMultipart2026..., which says nothing about what the client claimed).
    def open(source, filename:, max_size:, &)
      filename ||= client_filename(source)
      raise ArgumentError, "filename: is required for #{source.class}" if filename.to_s.empty?

      if source.is_a?(String) || source.respond_to?(:to_path)
        yield File.path(source), filename.to_s
      elsif source.respond_to?(:path) && source.path
        yield source.path.to_s, filename.to_s
      elsif source.respond_to?(:open) && source.respond_to?(:filename)
        source.open { |file| yield file.path, filename.to_s }
      elsif source.respond_to?(:read)
        copy_to_tempfile(source, max_size) { |path| yield path, filename.to_s }
      else
        raise ArgumentError, "unsupported upload source: #{source.class}"
      end
    end

    def client_filename(source)
      if source.respond_to?(:original_filename) then source.original_filename
      elsif source.respond_to?(:filename) then source.filename.to_s
      end
    end

    # Copies one byte past the limit so an oversized stream is still rejected as :too_large
    # without buffering all of it. The IO is rewound afterwards: the caller usually stores it
    # next (e.g. Active Storage attach(io:)), which would otherwise save an empty file.
    def copy_to_tempfile(io, max_size)
      Tempfile.create('upload_inspector', binmode: true) do |tmp|
        io.rewind if io.respond_to?(:rewind)
        IO.copy_stream(io, tmp, max_size + 1)
        io.rewind if io.respond_to?(:rewind)
        tmp.flush
        yield tmp.path
      end
    end
  end
end
