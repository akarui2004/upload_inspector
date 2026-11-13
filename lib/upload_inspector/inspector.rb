# frozen_string_literal: true

module UploadInspector
  # Detects the real type of a file and routes it to the structural inspector for that format.
  class Inspector
    include Rejectable

    PDF_MAGIC = '%PDF-'.b
    ZIP_MAGIC = "PK\x03\x04".b

    attr_reader :policy, :depth

    def initialize(policy, depth: 0)
      @policy = policy
      @depth = depth
    end

    # Boundary method: always returns a Result, rejecting on any error (fail closed).
    def call(path, filename:)
      Result.accept(verify!(path, filename))
    rescue Rejection => e
      Result.reject(e.reason, e.detail, detected_type: @detected_type)
    rescue StandardError => e
      Result.reject(:inspection_failed, "#{e.class}: #{e.message}", detected_type: @detected_type)
    end

    # Raises Rejection when the file is not proven safe; returns the detected MIME type.
    def verify!(path, filename)
      check_size!(path)
      @detected_type = detect_type(path, filename)
      reject!(:type_not_allowed, @detected_type) unless policy.permitted_type?(@detected_type)
      check_extension!(filename, @detected_type)
      inspect_structure!(path, @detected_type)
      @detected_type
    end

  private

    def check_size!(path)
      size = File.size(path)
      reject!(:empty_file) if size.zero?
      reject!(:too_large, "#{size} bytes") if size > policy.max_file_size
    end

    # Magic bytes win over the name; the name only refines a magic match (e.g. zip -> docx).
    def detect_type(path, filename)
      File.open(path, 'rb') { |io| Marcel::MimeType.for(io, name: filename.to_s) }
    end

    # The client-supplied extension must describe the same format, so a file cannot be
    # stored as one type and opened downstream as another (e.g. a PDF named x.zip).
    def check_extension!(filename, detected)
      by_name = Marcel::MimeType.for(name: filename.to_s)
      return if by_name == detected
      return if Marcel::Magic.child?(detected, by_name) || Marcel::Magic.child?(by_name, detected)

      reject!(:extension_mismatch, "#{File.extname(filename.to_s)} is #{by_name}, content is #{detected}")
    end

    def inspect_structure!(path, detected)
      head = File.binread(path, 8)
      verifiable = policy.allowed_types.include?(detected)
      if head.start_with?(PDF_MAGIC)
        PdfInspector.new(policy).verify!(path)
      elsif head.start_with?(ZIP_MAGIC) && verifiable
        ZipInspector.new(policy, depth:).verify!(path, detected)
      elsif verifiable && ImageInspector::FORMATS.key?(detected)
        ImageInspector.new(policy).verify!(path, detected)
      elsif verifiable && IsoBmffInspector::TYPES.include?(detected)
        IsoBmffInspector.new(policy).verify!(path, detected)
      elsif verifiable && TextInspector::TYPES.include?(detected)
        TextInspector.new(policy).verify!(path, detected)
      elsif verifiable && detected == SvgInspector::TYPE
        SvgInspector.new(policy).verify!(path)
      elsif !policy.allow_unverifiable.include?(detected)
        reject!(:unverifiable_type, detected)
      end
    end
  end
end
