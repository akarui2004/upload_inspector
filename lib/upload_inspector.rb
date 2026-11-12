# frozen_string_literal: true

require 'json'
require 'marcel'
require 'zip'
require 'zlib'

require_relative 'upload_inspector/version'
require_relative 'upload_inspector/result'
require_relative 'upload_inspector/policy'
require_relative 'upload_inspector/pdf_object_parser'
require_relative 'upload_inspector/pdf_inspector'
require_relative 'upload_inspector/ooxml_inspector'
require_relative 'upload_inspector/zip_inspector'
require_relative 'upload_inspector/inspector'
require_relative 'upload_inspector/sandbox'

# Fail-closed structural inspection of untrusted uploaded files.
# Only content proven to match a known-safe structure is accepted; anything
# unknown, unparsable, or erroring is rejected.
module UploadInspector
  # Inspects the file at +path+. Never raises on hostile input: always returns a Result.
  #
  #   UploadInspector.check('/tmp/x.pdf', filename: 'design.pdf', allowed_types: ['application/pdf'])
  #
  # +filename+ is the client-supplied name (its extension must agree with the real content).
  # +sandbox+ runs the inspection in a resource-limited child process (default true).
  # Other keywords are Policy options.
  def self.check(path, filename:, sandbox: true, **policy_options)
    policy = Policy.new(**policy_options)
    return Sandbox.run(path, filename:, policy:) if sandbox

    Inspector.new(policy).call(path, filename:)
  end
end
