# frozen_string_literal: true

module UploadInspector
  # Detects the real type of a file and routes it to the structural inspector for that format.
  class Inspector
    include Rejectable

    PDF_MAGIC = '%PDF-'.b
    ZIP_MAGIC = "PK\x03\x04".b
    MACRO_ENABLED = /macroenabled/i # docm, xlsm, pptm, xlsb, dotm, xltm, potm, ppsm...

    attr_reader :policy, :depth, :links

    # +links+ collects the URLs found, shared with the inspectors of zip members.
    def initialize(policy, depth: 0, links: [])
      @policy = policy
      @depth = depth
      @links = links
    end

    # Boundary method: always returns a Result, rejecting on any error (fail closed).
    def call(path, filename:)
      Result.accept(verify!(path, filename), links:)
    rescue Rejection => e
      Result.reject(e.reason, e.detail, detected_type: @detected_type, links:)
    rescue StandardError => e
      Result.reject(:inspection_failed, "#{e.class}: #{e.message}", detected_type: @detected_type, links:)
    end

    # Raises Rejection when the file is not proven safe; returns the detected MIME type.
    def verify!(path, filename)
      unsafe_name = Filename.unsafe_reason(filename)
      reject!(:filename_unsafe, unsafe_name) if unsafe_name
      check_size!(path)
      @detected_type = detect_type(path, filename)
      named_type = Marcel::MimeType.for(name: filename.to_s)
      check_permitted!(@detected_type, named_type)
      check_extension!(filename, named_type, @detected_type)
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
    # Compound files (legacy Office) are typed from their directory, which Marcel cannot read.
    def detect_type(path, filename)
      if File.binread(path, CfbReader::MAGIC.bytesize) == CfbReader::MAGIC
        type = CfbReader.open(path) { |reader| OleInspector.detect_type(reader) }
        return type if type
      end
      File.open(path, 'rb') { |io| Marcel::MimeType.for(io, name: filename.to_s) }
    end

    # Macro-enabled and legacy Office get their own reasons, so users can be told to re-save.
    def check_permitted!(detected, named_type)
      if [detected, named_type].any? { |type| type.match?(MACRO_ENABLED) }
        reject!(:office_macro_enabled, "#{detected} named #{named_type}")
      end
      return if policy.permitted_type?(detected)

      reject!(OleInspector::TYPES.include?(detected) ? :legacy_office : :type_not_allowed, detected)
    end

    # The client-supplied extension must describe the same format, so a file cannot be
    # stored as one type and opened downstream as another (e.g. a PDF named x.zip).
    def check_extension!(filename, by_name, detected)
      return if by_name == detected
      return if Marcel::Magic.child?(detected, by_name) || Marcel::Magic.child?(by_name, detected)

      reject!(:extension_mismatch, "#{File.extname(filename.to_s)} is #{by_name}, content is #{detected}")
    end

    def inspect_structure!(path, detected)
      head = File.binread(path, 8)
      verifiable = policy.allowed_types.include?(detected)
      if head.start_with?(PDF_MAGIC)
        PdfInspector.new(policy, links:).verify!(path)
      elsif head.start_with?(ZIP_MAGIC) && verifiable
        ZipInspector.new(policy, depth:, links:).verify!(path, detected)
      elsif head == CfbReader::MAGIC && verifiable && OleInspector::TYPES.include?(detected)
        CfbReader.open(path) { |reader| OleInspector.new(policy).verify!(reader) }
      elsif verifiable && detected == RtfInspector::TYPE
        RtfInspector.new(policy, links:).verify!(path)
      elsif verifiable && ImageInspector::FORMATS.key?(detected)
        ImageInspector.new(policy).verify!(path, detected)
      elsif verifiable && IsoBmffInspector::TYPES.include?(detected)
        IsoBmffInspector.new(policy).verify!(path, detected)
      elsif verifiable && TextInspector::TYPES.include?(detected)
        TextInspector.new(policy).verify!(path, detected)
      elsif verifiable && detected == SvgInspector::TYPE
        SvgInspector.new(policy, links:).verify!(path)
      elsif !policy.allow_unverifiable.include?(detected)
        reject!(:unverifiable_type, detected)
      end
    end
  end
end
