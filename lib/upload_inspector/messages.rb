# frozen_string_literal: true

module UploadInspector
  # End-user messages for rejection reasons, worded to follow an attribute name
  # ("Document is password-protected"). Override or translate them under
  # upload_inspector.errors.<reason> (fallback upload_inspector.errors.default) in any I18n
  # locale file; these English strings apply when no translation exists or I18n is not loaded.
  module Messages
    DAMAGED = 'is damaged or not a valid file'
    NOT_CHECKED = 'could not be checked, please try again'
    DEFAULTS = {
      default: 'contains content that is not allowed',
      type_not_allowed: 'is not an allowed file type',
      unverifiable_type: 'is not an allowed file type',
      extension_mismatch: 'does not match its file extension',
      too_large: 'is too large',
      text_too_large: 'is too large',
      svg_too_large: 'is too large',
      empty_file: 'is empty',
      pdf_encrypted: 'is password-protected',
      zip_encrypted_entry: 'is password-protected',
      image_too_many_pixels: 'has image dimensions that are too large',
      text_unsupported_encoding: 'must be saved as UTF-8 text',
      text_binary_content: 'is not a text file',
      csv_formula: 'contains spreadsheet formulas',
      image_malformed: DAMAGED, media_malformed: DAMAGED, pdf_unparsable: DAMAGED,
      zip_unparsable: DAMAGED, zip_empty: DAMAGED, svg_unparsable: DAMAGED, ooxml_malformed_xml: DAMAGED,
      timeout: NOT_CHECKED, resource_limit: NOT_CHECKED, inspection_failed: NOT_CHECKED, sandbox_failed: NOT_CHECKED,
    }.freeze

    module_function

    def for(reason)
      english = DEFAULTS.fetch(reason.to_sym, DEFAULTS[:default])
      return english unless defined?(I18n)

      I18n.t("upload_inspector.errors.#{reason}", default: [:'upload_inspector.errors.default', english])
    end
  end
end
