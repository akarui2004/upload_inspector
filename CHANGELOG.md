# Changelog

## 0.9.0

- `UploadInspector.sanitize(source, to:, ...)`: content disarm and reconstruction. Checks the
  upload, writes a cleaned copy holding only the parts known to be safe, checks the copy again and
  moves it to `to:` (`Result#sanitized_path`); nothing is written when either check rejects.
  Runs in the sandbox like `check`.
  - PNG, JPEG, GIF, WebP: metadata (EXIF with GPS, XMP), comments, unknown chunks and extra MPF
    images are dropped; image data, color profiles and animation are kept.
    `keep_orientation: true` keeps the JPEG Orientation tag.
  - HEIC, HEIF, AVIF, MP4, QuickTime: unknown top-level boxes, user data and metadata in `moov`
    and its tracks, and Exif/XMP items are zero-filled in place (no offset moves) or removed at
    the end of the file.
  - SVG: rebuilt from an allowlist of elements and attributes (SMIL animation included), without
    comments, processing instructions or metadata, entities normalized, UTF-8.
  - CSV/TSV/TXT: copied; `neutralize_csv_formulas: true` writes formula cells with a leading `'`.
  - `reencode: true`: decode and encode raster images with libvips (optional `ruby-vips` gem; only
    this option raises `ArgumentError` without it).
  - Other types are rejected as `:sanitize_unsupported`.
- `Result#sanitized_path` (nil except for a successful `sanitize`).
- With ActiveSupport loaded, `sanitize` publishes `sanitize.upload_inspector`.

## 0.8.1

Security fixes for checks added in 0.8.0; upgrade if you allow legacy Office, OpenDocument or rely
on `:pdf_auto_action`.

- Legacy Office: stream names are compared case-insensitively, as Office reads them. A
  `workbook` stream with an Excel 4.0 macro sheet was not inspected. A compound file holding no
  Office stream is now `application/x-ole-storage` whatever its name.
- OpenDocument: links climbing out of the package mid-path, percent-encoded or with backslashes
  (`Pictures/../../x`, `%2e%2e/x`, `..\x`) are rejected. Formulas using `WEBSERVICE`,
  `FILTERXML`, `INDIRECT`, UNC paths or references into other documents (`'https://...'#`) are
  rejected as `:odf_dangerous_formula`.
- PDF: automatic actions stored in compressed object streams are resolved, so an `/OpenAction`
  pointing to a URI action there is rejected. An action reference that may sit in an object
  stream that cannot be indexed (uncompressed, indirect or malformed `/First`/`/N`) is rejected
  as `:pdf_unparsable`. Each reference is followed once, at most 1000 objects.

## 0.8.0

- Legacy Office (`.doc/.xls/.ppt/.msg`) is rejected as `:legacy_office` with a "save as
  .docx/.xlsx/.pptx" message (previously `:type_not_allowed`). With the type in `allowed_types`, the Compound File is
  read in pure Ruby and VBA/XLM macros, OLE objects, ActiveX, mail attachments, encryption, Word
  DDE/INCLUDE fields, Excel external links and PowerPoint program actions are rejected (`:ole_*`).
- Macro-enabled OOXML (`.docm/.xlsm/.pptm/.xlsb/.dotm`...) is rejected as `:office_macro_enabled`;
  password-protected `.docx/.xlsx/.pptx` (and `.doc/.xls/.ppt`, ODF) as `:office_encrypted`.
  OOXML templates (`.dotx/.potx/.xltx`) are verified like documents.
- RTF (`application/rtf`): tokenizer rejecting OLE objects, `\datastore`, remote templates,
  dangerous fields and `file:` hyperlinks (`:rtf_*`).
- OpenDocument (`.odt/.ods/.odp`): allowlist of parts, rejects macros, scripts, OLE objects,
  DDE, encrypted parts and links leaving the package (`:odf_*`).
- PDF: a link opened with no click (`/OpenAction` or `/AA` reaching a URI action) is rejected as
  `:pdf_auto_action`; `pdf_links: :reject` rejects every link (`:pdf_link`).
- `Result#links`: web/mail links found in PDF, OOXML, OpenDocument, RTF and SVG files (max 100),
  carried through the sandbox, to check against a URL reputation service.

## 0.7.2

- Rewritten code to clean up.

## 0.7.1

- Documentation site: https://akarui2004.github.io/upload_inspector (gem description, homepage and
  documentation link point to it).

## 0.7.0

- Text: `.txt/.csv/.tsv` with HTML, SVG or server-side tags (`<script`, `<html`, `<svg`, `<img`,
  `<?php`, `<%`, ...) are rejected as `:text_markup` (opt out with `allow_text_markup: true`).
- File names: bidi overrides, control characters and an executable extension before the last one
  (`shell.php.jpg`, `invoice.exe.pdf`, also inside zips) are rejected as `:filename_unsafe`. A
  name that is not valid UTF-8 no longer raises from the sandbox.
- `UploadInspector.safe_filename(name, detected_type:)`: a name safe to store and serve.
- `UploadInspector.safe_headers(result, filename:, inline:)`: response headers for serving a
  checked file (download by default, `nosniff`, sandboxing CSP); README guide on serving uploads.
- `UploadInspector::Presets` (`IMAGES`, `DOCUMENTS`, `OFFICE`, `PDF`, `SVG`, `MEDIA`, `TEXT`).
- Shadow mode: `mode: :report` on `check`, `check_s3`, the validator and the job accepts every
  file and sets `Result#would_reject`.
- Instrumentation: `check.upload_inspector` via `ActiveSupport::Notifications` when loaded.
- `SECURITY.md` (private vulnerability reporting) and `THREAT_MODEL.md`.

## 0.6.0

- Text: `text/csv`, `text/tab-separated-values` and `text/plain` in `allowed_types` are verified:
  valid UTF-8, no NUL/control characters, CSV/TSV cells that would run as a spreadsheet
  function or DDE rejected (`:csv_formula`, opt out with `allow_csv_formulas: true`). New reasons
  `:text_too_large`, `:text_unsupported_encoding`, `:text_binary_content`, `:csv_formula`.
- Rails: `validates :file, upload_inspector: {...}` checks request uploads before save;
  `UploadInspector::InspectJob` checks stored attachments in the background, purges unsafe ones
  and calls `on_unsafe`. Both autoload; Rails is still not a dependency.
- `Result#message`: end-user message per reason, translatable under `upload_inspector.errors.*`.
- Checking an IO now rewinds it afterwards, so it can still be stored (`attach(io:)`).

## 0.5.0

- HEIC, HEIF, AVIF, MP4 and QuickTime in `allowed_types` are now structurally verified (box
  bounds, no appended data, `ftyp` brand matching the detected type, `meta`/`moov` present,
  declared dimensions within `max_image_pixels`) instead of `:unverifiable_type`. New reasons
  `:media_malformed`, `:media_brand_mismatch`.

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
