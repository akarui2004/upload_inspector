# Changelog

## 0.4.0

- `check` accepts upload objects: Rails/Rack `UploadedFile` and Active Storage blobs/attachments
  (name taken from the upload), `File`/`Tempfile`/`Pathname` and readable IO. `filename:` is
  optional when the source carries a name.
- `check_s3` inspects an S3 object (e.g. uploaded via presigned URL) with any `Aws::S3::Client`:
  oversized objects are rejected from `HeadObject` without download; the download is pinned to
  the checked ETag.
- Active Storage blobs larger than `max_file_size` are rejected from `byte_size` before download.
  README documents bounding disk, download time and upload size.
## 0.3.0

- Images: PNG, JPEG, GIF and WebP in `allowed_types` are now structurally verified (bounds,
  `max_image_pixels`, no data after the end of the image) instead of `:unverifiable_type`.
  New reasons `:image_malformed`, `:image_too_many_pixels`, `:image_trailing_data`.
- SVG: `image/svg+xml` in `allowed_types` is verified as static (no script, event handlers,
  foreign content, DTD entities or references outside the file). New reasons
  `:svg_active_content`, `:svg_external_reference`, `:svg_dtd`, `:svg_unparsable`,
  `:svg_unsupported_encoding`, `:svg_too_large`.
- OOXML: checks no longer trust part paths. A main document stored as `media/x.png`
  (`:ooxml_disguised_part`), DDE fields or formulas in a part outside `word/` / `xl/`, and
  connections, DDE/external links or macro sheets under another name
  (`:ooxml_forbidden_content`, `:ooxml_forbidden_content_type`) are rejected. Relationship
  types are an allowlist; namespace-prefixed `TargetMode` decoys are ignored.
- OOXML: XML is tokenized in linear time (a ~1 kB upload could burn the whole timeout);
  malformed XML and encodings other than UTF-8/ASCII/Latin-1 are rejected
  (`:ooxml_malformed_xml`).
- PDF: reject attachments that need no `/EmbeddedFile` type or name tree (`/EF`,
  `/FileAttachment`, `/Filespec`, `/Collection`).
- Sandbox: temp files of a child killed on timeout or a resource limit are removed.

## 0.2.0

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
