# frozen_string_literal: true

module UploadInspector
  # Policy for legacy Office files (.doc/.xls/.ppt/.msg) stored in a Compound File (see CfbReader).
  #
  # These formats are rejected as :legacy_office unless their type is in allowed_types. When
  # opted in, the directory and the few records that matter are read: VBA/XLM macros, embedded
  # OLE objects and ActiveX, mail attachments, encryption, Word fields that fetch or run things,
  # Excel links to other workbooks/DDE and PowerPoint actions that run programs are rejected.
  class OleInspector
    include Rejectable

    WORD = 'application/msword'
    EXCEL = 'application/vnd.ms-excel'
    POWERPOINT = 'application/vnd.ms-powerpoint'
    OUTLOOK = 'application/vnd.ms-outlook'
    TYPES = [WORD, EXCEL, POWERPOINT, OUTLOOK].freeze
    # Compound File names compare case-insensitively (MS-CFB), so do all lookups here.
    MAIN_STREAMS = { 'worddocument' => WORD, 'workbook' => EXCEL, 'book' => EXCEL, 'powerpoint document' => POWERPOINT }.freeze
    OUTLOOK_PROPERTY = /\A__substg1\.0_/i

    MACRO_ENTRY = /\A(?:Macros|_VBA_PROJECT|_VBA_PROJECT_CUR|VBA)\z/i
    # Word/Excel embedded objects, OLE native data, Outlook attachments.
    EMBEDDED_ENTRY = /\A(?:ObjectPool|\u0001Ole10Native|MBD\h{8}|__attach_version1\.0_#\h{8})\z/i
    ENCRYPTED_ENTRY = /\A(?:EncryptionInfo|EncryptedPackage|EncryptedSummary)\z/i
    DANGEROUS_FIELD = /\x13[\s"]*(DDEAUTO|DDE|INCLUDETEXT|INCLUDEPICTURE|INCLUDE|IMPORT|LINK|QUOTE|DATABASE|MACROBUTTON)(?![A-Z])/ni

    WORD_ENCRYPTED_FLAG = 0x0100 # FIB fEncrypted
    BIFF_BOF = 0x0809
    BIFF_EOF = 0x000A
    BIFF_FILEPASS = 0x002F
    BIFF_BOUNDSHEET = 0x0085
    BIFF_SUPBOOK = 0x01AE
    MACRO_SHEET_TYPES = { 1 => 'Excel 4.0 macro sheet', 6 => 'VBA module sheet' }.freeze
    LOCAL_SUPBOOK = [0x0401, 0x3A01].freeze # this workbook, add-in functions
    PPT_OLE_STORAGE = 0x1011 # OLE object, ActiveX control or VBA project
    PPT_INTERACTIVE_INFO = 0x0FF3
    PPT_CRYPT_SESSION = 0x2F14
    PPT_RUNNING_ACTIONS = { 1 => 'macro', 2 => 'run program', 5 => 'OLE verb' }.freeze

    # Real type from the directory, or nil for compound files that are not Office documents
    # (the caller must not fall back to the name: a .xls without a workbook is not a workbook).
    # Encrypted OOXML is a compound file too and is rejected here, whatever its type.
    def self.detect_type(reader)
      names = reader.entries.map { |entry| entry.name.downcase }
      raise Rejection.new(:office_encrypted, 'EncryptedPackage') if names.include?('encryptedpackage')

      MAIN_STREAMS.each { |stream, type| return type if names.include?(stream) }
      OUTLOOK if names.any? { |name| name.match?(OUTLOOK_PROPERTY) }
    end

    def initialize(policy)
      @policy = policy
    end

    def verify!(reader)
      reader.entries.each { |entry| check_entry!(entry.name) }
      reader.entries.each do |entry|
        next unless entry.stream?

        case entry.name.downcase
        when 'worddocument' then check_word!(read(reader, entry))
        when 'workbook', 'book' then check_workbook!(read(reader, entry))
        when 'powerpoint document' then check_presentation!(read(reader, entry))
        end
      end
    end

  private

    attr_reader :policy

    def check_entry!(name)
      reject!(:ole_macro, name) if name.match?(MACRO_ENTRY)
      reject!(:ole_embedded_object, name.delete("\u0001")) if name.match?(EMBEDDED_ENTRY)
      reject!(:office_encrypted, name) if name.match?(ENCRYPTED_ENTRY)
    end

    def read(reader, entry)
      reject!(:ole_too_large, "#{entry.name} exceeds #{policy.max_inflate_size} bytes") if entry.size > policy.max_inflate_size
      reader.read(entry, entry.size)
    end

    # Field codes sit in the document text between 0x13 and 0x14; text is 8-bit or UTF-16LE,
    # so NULs are dropped to read both the same way.
    # ponytail: assumes a field code is stored contiguously; a fast-saved file can split it across
    # pieces of the piece table, which would need the Table stream to reassemble.
    def check_word!(data)
      reject!(:ole_malformed, 'WordDocument too short') if data.bytesize < 12
      reject!(:office_encrypted, 'WordDocument') if data.unpack1('@10v').anybits?(WORD_ENCRYPTED_FLAG)

      match = data.delete("\0").match(DANGEROUS_FIELD)
      reject!(:ole_dangerous_field, match[1].upcase) if match
    end

    # Reads the workbook globals: BOF, sheet list, links to other workbooks, up to its EOF record.
    def check_workbook!(data)
      each_biff_record(data) do |type, body, index|
        reject!(:ole_malformed, 'Workbook does not start with BOF') if index.zero? && type != BIFF_BOF
        case type
        when BIFF_EOF then break
        when BIFF_FILEPASS then reject!(:office_encrypted, 'Workbook')
        when BIFF_BOUNDSHEET
          kind = MACRO_SHEET_TYPES[body.getbyte(5)]
          reject!(:ole_macro, kind) if kind
        when BIFF_SUPBOOK
          reject!(:ole_external_link, 'link to another workbook or DDE') unless LOCAL_SUPBOOK.include?(body.unpack1('@2v'))
        end
      end
      reject!(:ole_malformed, 'Workbook globals without EOF') unless @eof
    end

    # Walks every record, descending into containers (version 0xF).
    def check_presentation!(data)
      position = 0
      while position + 8 <= data.bytesize
        version_instance, type, length = data.unpack("@#{position}vvV")
        container = (version_instance & 0xF) == 0xF
        reject!(:ole_malformed, 'PowerPoint record past the end') if position + 8 + length > data.bytesize
        reject!(:ole_embedded_object, 'PowerPoint OLE object, ActiveX control or VBA project') if type == PPT_OLE_STORAGE
        reject!(:office_encrypted, 'PowerPoint Document') if type == PPT_CRYPT_SESSION
        if type == PPT_INTERACTIVE_INFO && length >= 9
          action = PPT_RUNNING_ACTIONS[data.getbyte(position + 16)]
          reject!(:ole_program_action, action) if action
        end
        position += 8 + (container ? 0 : length)
      end
    end

    # BIFF records: 2-byte type, 2-byte length, body. Sets @eof when the loop stops on EOF.
    def each_biff_record(data)
      position = 0
      index = 0
      @eof = false
      while position + 4 <= data.bytesize
        type, length = data.unpack("@#{position}vv")
        body = data.byteslice(position + 4, length)
        reject!(:ole_malformed, 'record past the end') if body.bytesize < length
        @eof = type == BIFF_EOF
        yield type, body, index
        position += 4 + length
        index += 1
      end
    end
  end
end
