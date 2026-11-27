# frozen_string_literal: true

require 'tmpdir'
require 'upload_inspector'

class Shrine
  module Plugins
    # Shrine plugin: validates attached files with UploadInspector.check (the errors land in
    # attacher.errors, alongside the Attacher.validate block) and, with sanitize: true, stores a
    # cleaned copy on promote (see UploadInspector.sanitize).
    #
    #   class DocumentUploader < Shrine
    #     plugin :upload_inspector, allowed_types: UploadInspector::Presets::DOCUMENTS, sanitize: true
    #   end
    #
    # Other options are UploadInspector.check keywords. Types that cannot be cleaned (PDF, Office)
    # are promoted as they are; they passed the check when attached. A cleanable type that
    # cannot be rewritten raises Rejected rather than storing the original with its metadata.
    module UploadInspector
      # Raised by promote when the cleaned copy is rejected.
      class Rejected < Shrine::Error; end

      def self.load_dependencies(uploader, **)
        uploader.plugin :validation
      end

      def self.configure(uploader, sanitize: false, **check_options)
        uploader.opts[:upload_inspector] = { sanitize:, check: check_options }
      end

      module AttacherMethods
        # Result of the last check, nil before one ran.
        attr_reader :upload_inspector_result

        def promote(storage: store_key, **upload_options)
          options = shrine_class.opts[:upload_inspector]
          return super unless options[:sanitize]

          file.download do |tempfile|
            Dir.mktmpdir('upload_inspector') do |dir|
              output = File.join(dir, 'sanitized')
              result = ::UploadInspector.sanitize(tempfile, to: output, filename: upload_inspector_filename,
                                                            **options[:check].except(:mode))
              uncleanable = !::UploadInspector::Sanitizer.supported?(result.detected_type)
              return super if result.reason == :sanitize_unsupported && uncleanable
              raise Rejected, "#{result.reason}: #{result.message}" unless result.safe?

              File.open(output, 'rb') do |io|
                set upload(io, storage, action: :store, metadata: file.metadata.merge('size' => io.size),
                                       **upload_options)
              end
            end
          end
        end

        private

        def _validate(**)
          file.download do |tempfile|
            @upload_inspector_result = ::UploadInspector.check(tempfile, filename: upload_inspector_filename,
                                                                         **shrine_class.opts[:upload_inspector][:check])
          end
          errors << upload_inspector_result.message unless upload_inspector_result.safe?
          super
        end

        def upload_inspector_filename = file.original_filename || File.basename(file.id)
      end
    end

    register_plugin(:upload_inspector, UploadInspector)
  end
end
