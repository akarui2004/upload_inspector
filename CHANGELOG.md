# Changelog

## Unreleased

- PDF: object streams are found by `/ObjStm` or `/First` and their dictionaries parsed with a real
  lexer; comments, strings, fake object headers, indirect `/Filter` values and a missing `/Type`
  no longer hide JavaScript inside them.
- PDF: reject URI links that are not http(s), mailto or relative (`:pdf_unsafe_uri`), and
  JBIG2, 3D (U3D/PRC) and PostScript content (`:pdf_risky_feature`).
- OOXML: quote-aware relationship parsing; reject macro/OLE/ActiveX/altChunk relationship types
  (`:ooxml_forbidden_relationship`), DATABASE/INCLUDE/MACROBUTTON fields, entity-encoded or CDATA
  DDE formulas and defined names, entity-encoded PowerPoint actions and macro content types,
  external data connections and Power Query (`:ooxml_external_data`).
- `timeout` must be a positive number (raises `ArgumentError` instead of failing mid-check).
- Hostile-sample corpus (`test/sample_virus_malware.rb`) with inert payloads only.

## 0.1.0

- Initial release: fail-closed inspection of PDF, OOXML (docx/pptx/xlsx) and zip uploads with a
  resource-limited sandbox process.
