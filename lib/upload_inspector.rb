# frozen_string_literal: true

require 'json'
require 'marcel'
require 'zip'
require 'zlib'

require_relative 'upload_inspector/version'
require_relative 'upload_inspector/result'
require_relative 'upload_inspector/policy'
require_relative 'upload_inspector/xml_scanner'
require_relative 'upload_inspector/pdf_object_parser'
require_relative 'upload_inspector/pdf_inspector'
require_relative 'upload_inspector/svg_inspector'
require_relative 'upload_inspector/image_inspector'
require_relative 'upload_inspector/iso_bmff_inspector'
require_relative 'upload_inspector/ooxml_inspector'
require_relative 'upload_inspector/zip_inspector'
require_relative 'upload_inspector/inspector'
require_relative 'upload_inspector/sandbox'
require_relative 'upload_inspector/source'
require_relative 'upload_inspector/s3'

# Fail-closed structural inspection of untrusted uploaded files.
# Only content proven to match a known-safe structure is accepted; anything
# unknown, unparsable, or erroring is rejected.
module UploadInspector
  # Inspects an upload. Never raises on hostile input: always returns a Result.
  #
  #   UploadInspector.check('/tmp/x.pdf', filename: 'design.pdf', allowed_types: ['application/pdf'])
  #   UploadInspector.check(params[:file])           # Rails UploadedFile: name from original_filename
  #   UploadInspector.check(record.document)         # Active Storage attachment or blob
  #
  # +source+ is a path, File/Tempfile, Rails/Rack UploadedFile, Active Storage blob/attachment or
  # readable IO (see Source). +filename+ is the client-supplied name (its extension must agree
  # with the real content); taken from the source when it carries one, required otherwise.
  # +sandbox+ runs the inspection in a resource-limited child process (default true).
  # Other keywords are Policy options.
  def self.check(source, filename: nil, sandbox: true, **policy_options)
    policy = Policy.new(**policy_options)
    # Active Storage knows the size up front: reject before downloading the blob to disk.
    size = source.respond_to?(:byte_size) ? source.byte_size.to_i : 0
    return Result.reject(:too_large, "#{size} bytes") if size > policy.max_file_size

    Source.open(source, filename:, max_size: policy.max_file_size) do |path, name|
      next Sandbox.run(path, filename: name, policy:) if sandbox

      Inspector.new(policy).call(path, filename: name)
    end
  end

  # Downloads and inspects an S3 object, e.g. one uploaded through a presigned URL.
  # +client+ is an Aws::S3::Client; +filename+ defaults to the key's basename.
  #
  #   result = UploadInspector.check_s3(client: s3, bucket: 'uploads', key: 'tmp/abc/report.pdf')
  #   s3.delete_object(bucket: 'uploads', key: 'tmp/abc/report.pdf') unless result.safe?
  def self.check_s3(client:, bucket:, key:, filename: nil, version_id: nil, sandbox: true, **policy_options)
    S3.check(client:, bucket:, key:, filename:, version_id:, sandbox:, policy: Policy.new(**policy_options))
  end
end
