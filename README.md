# upload_inspector

Fail-closed structural inspection of untrusted uploaded files for any Ruby or Rails app, and
**content disarm and reconstruction**: clean copies of uploads with metadata and hidden payloads removed.
Checks a path, a Rails upload, an Active Storage attachment, any IO, or an S3 object uploaded
through a presigned URL.

A file is accepted only when its structure is proven to match a known-safe shape. Anything unknown,
unparsable, encrypted, oversized, or erroring is rejected. Pure Ruby (`marcel`, `rubyzip`), no AV engine,
no native parsers, nothing is rendered or executed (libvips only for the optional re-encode).

> **New in 0.9: `UploadInspector.sanitize`.** Writes a clean copy that keeps only the parts known
> to be safe: EXIF with GPS location, XMP, comments, unknown chunks and payloads hidden in them
> (a `<?php` web shell in a JPEG comment, a zip in an MP4 box) are removed from PNG, JPEG, GIF,
> WebP, HEIC, AVIF, MP4 and QuickTime; SVG is rebuilt from an allowlist; CSV formulas can be
> neutralized; `reencode: true` re-encodes images through libvips. The copy is checked again
> before it is written.
>
> ```ruby
> result = UploadInspector.sanitize(params[:file], to: clean_path, allowed_types: UploadInspector::Presets::IMAGES)
> store(result.sanitized_path) if result.safe?
> ```
>
> See [Sanitizing uploads (CDR)](#sanitizing-uploads-cdr).

> **Not an antivirus.** It blocks structural attack vectors: disguised executables, macros, PDF
> JavaScript, OLE objects, remote templates, DDE, zip bombs, image polyglots, scripted SVG and
> CSV injection. It does not detect malware signatures or exploits hidden inside otherwise valid
> content by itself: pass `scanner:` (ClamAV built in, no extra gem) or check Amazon GuardDuty
> Malware Protection for S3's tag, see [Malware scanning](#malware-scanning).
>
> What it does and does not defend against: [THREAT_MODEL.md](THREAT_MODEL.md). Report
> vulnerabilities privately: [SECURITY.md](SECURITY.md).

## What it checks

| Format | Checks |
|---|---|
| All | real type by magic bytes (Marcel) must be allowlisted; file extension must agree with content; size limit; file name without bidi overrides (`invoice\u202Efdp.exe`), control characters or an executable extension before the last one (`shell.php.jpg`, `invoice.exe.pdf`) |
| PDF (and PDF-based `.ai`) | rejects `/JavaScript /JS /Launch /EmbeddedFile(s) /EF /FileAttachment /Filespec /Collection /RichMedia /XFA /SubmitForm /ImportData /GoToR /GoToE /Rendition`, hex-escaped spellings included, also inside compressed object streams (located by `/ObjStm` or `/First` and parsed with a real PDF lexer, so comments, strings and fake headers cannot hide them); rejects risky parsers (`/JBIG2Decode`, 3D/U3D/PRC, PostScript XObjects), URI links other than http(s)/mailto/relative (`file:`, UNC, `javascript:`, indirect values), links opened with no click (a URI action reached from `/OpenAction` or an `/AA` additional action, directly, through `/Next` or an indirect object, also one stored in an object stream), encrypted PDFs and unsupported object-stream filters. `pdf_links: :reject` rejects every link |
| docx / pptx / xlsx (and templates dotx / potx / xltx) | every part name must match an allowlist, and no check trusts a part's path (Office finds parts through content types and relationships): every part is inspected as XML or proven not to be XML, every XML part gets every check, and only relationship types known to be passive are accepted. Rejects VBA, `embeddings/`, `activeX/`, macro sheets, external data (connections, query tables, external/DDE/OLE links, Power Query) by part name, content type, relationship type and element, macro content types, DTDs, external relationships other than http(s)/mailto hyperlinks, Word DDE/INCLUDE(TEXT/PICTURE)/IMPORT/LINK/QUOTE/DATABASE/MACROBUTTON fields, PowerPoint program/macro actions, Excel DDE formulas and defined names, malformed XML, XML that is not UTF-8/ASCII/Latin-1; checks run on entity-decoded text and CDATA. Macro-enabled files (`.docm .xlsm .pptm .xlsb .dotm ...`) are always rejected as `:office_macro_enabled`, password-protected ones as `:office_encrypted` |
| doc / xls / ppt / msg (Office 97-2003) | rejected as `:legacy_office` ("must be saved as .docx, .xlsx or .pptx") unless the type is in `allowed_types`. When allowed, the Compound File container is read (bounds-checked; loops, out-of-range sectors and truncation are `:ole_malformed`) and rejects VBA (`Macros`, `_VBA_PROJECT(_CUR)`, `VBA`), Excel 4.0 macro sheets, embedded OLE objects (`ObjectPool`, `Ole10Native`, Excel `MBD` storages, PowerPoint OLE/ActiveX/VBA records), Outlook attachments, encryption, Word DDE/INCLUDE(TEXT/PICTURE)/IMPORT/LINK/QUOTE/DATABASE/MACROBUTTON fields, Excel links to other workbooks/DDE and PowerPoint actions running a program, macro or OLE verb. Word fields split across a fast-saved piece table are not reassembled |
| RTF | tokenized like Word reads it (groups, control words, hex escapes, `\bin` data, `\u` with fallback characters): rejects every `\obj*` control word (OLE objects such as Equation Editor exploits, auto-updating links), `\datastore`, `\*\template`, `\dibitmap` pictures, fields that fetch or run things and `HYPERLINK` to anything but http(s)/mailto/bookmarks; groups must balance, nest at most 256 deep and nothing may follow the document |
| odt / ods / odp | `mimetype` must be the first member and match; every part name must match an allowlist. Rejects Basic/script/dialog libraries (by part, manifest path and media type), encrypted parts, OLE objects, script event listeners, inline scripts, macro fields, presentation actions running a program or OLE verb, applets/plugins/frames, DDE, DTDs, `DDE()`/`WEBSERVICE()`/`FILTERXML()`/`INDIRECT()` formulas, `file:`/UNC paths and references into other documents (`'file:...'#$Sheet1.A1`), and any `xlink:href` leaving the package (schemes, absolute paths, `..` segments, also percent-encoded or with backslashes) other than http(s)/mailto hyperlinks. Embedded charts are inspected like the rest |
| PNG / JPEG / GIF / WebP | container walked block by block (nothing is decoded): every length must stay inside the file, declared dimensions within `max_image_pixels`, and nothing may follow the end of the image (appended scripts or archives). JPEG files holding several images back to back (HDR gain maps, MPF) are accepted; other trailers (motion-photo video, vendor data) are rejected, re-encode those |
| HEIC / HEIF / AVIF / MP4 / QuickTime | box structure walked (nothing is decoded): every box length must stay inside its parent and the boxes must cover the file exactly (no appended data), `ftyp` must come first and name a brand of the detected type, images need a `meta` box and video a `moov` box, declared image (`ispe`) and track (`tkhd`) dimensions within `max_image_pixels`. Files whose brand Marcel does not know are reported as QuickTime and rejected unless the brand is `qt  `; data hidden inside a box (e.g. a zip in a trailing `free` box) is not detected |
| SVG | static only: rejects script elements, `on*` handlers, `javascript:`/`data:` links (also set through animation), XHTML/MathML content, stylesheet processing instructions, DTDs other than the standard W3C DOCTYPE, CSS `@import`/escapes, and any reference outside the file (`href`, `src`, CSS `url()`) except `#fragment`, embedded `data:image/png|jpeg|gif|webp` and http(s)/mailto links on `<a>` |
| CSV / TSV / TXT | valid UTF-8 (BOM allowed; UTF-16 and legacy code pages rejected), no NUL or control characters other than tab/CR/LF, at most `max_inflate_size`. No HTML, SVG or server-side tags (`<script`, `<html`, `<svg`, `<img`, `<iframe`, `<?php`, `<%`, ..., any tag with an `on*=` handler, and at the start the signatures browsers sniff as HTML such as `<p>`, `<div>`, `<!--`; `a<b` and `<b>` mid-text are fine), which a sniffing browser would render as a page; `allow_text_markup: true` turns this off. CSV/TSV also reject cells a spreadsheet would run as a function call or DDE (`=HYPERLINK(...)`, `+cmd\|...`, `@SUM(...)`), found after any comma, semicolon or tab and inside quotes; negative numbers, phone numbers, `@handles` and plain arithmetic are accepted. `allow_csv_formulas: true` turns this off |
| zip | path traversal, symlinks, encrypted entries, duplicates, entry/total size and compression-ratio limits, nested archives; every member extracted (bounded) and inspected with the same policy |
| Others | rejected unless listed in `allow_unverifiable` (type + extension check only) |

### Large PDFs can be rejected by chance

PDF names are searched in the raw bytes, compressed image data included, so random bytes that
happen to spell a short blocked name (`/JS`, `/3D`, `/EF`) reject a clean file as
`:pdf_active_content` or `:pdf_risky_feature`. The estimated chance is about 1.2% per MB of
compressed stream data: roughly 1 in 8 for a 10 MB PDF, 1 in 2 for 50 MB, 7 in 10 for 100 MB.
Text-only PDFs are unaffected. For image-heavy PDFs (scans, `.ai` artwork) keep uploads to a few
MB, or expect to ask users to re-export. Skipping stream data is not an option without
following the cross-reference table the way a reader does, because objects can hide in it.

Images, SVG, media, text, legacy Office, RTF and OpenDocument are verified when their MIME type is in `allowed_types`
(`image/png image/jpeg image/gif image/webp image/svg+xml image/heic image/heif image/avif video/mp4 video/quicktime text/csv text/tab-separated-values text/plain application/msword application/vnd.ms-excel application/vnd.ms-powerpoint application/vnd.ms-outlook application/rtf application/vnd.oasis.opendocument.text application/vnd.oasis.opendocument.spreadsheet application/vnd.oasis.opendocument.presentation`, and the OOXML templates `application/vnd.openxmlformats-officedocument.{wordprocessingml,presentationml,spreadsheetml}.template`). Listing them in `allow_unverifiable`
instead skips these checks.

## Install

```ruby
gem 'upload_inspector'
```

Requires Ruby >= 3.2.

## Usage

- [Quick start](#quick-start)
- [What you can pass in](#what-you-can-pass-in)
- [Rails validator and job](#rails-validator-and-job)
- [Presets](#presets)
- [Shadow mode and instrumentation](#shadow-mode-and-instrumentation)
- [Serving uploads safely](#serving-uploads-safely)
- [Sanitizing uploads (CDR)](#sanitizing-uploads-cdr)
- [Error messages](#error-messages)
- [S3 (presigned URL uploads)](#s3-presigned-url-uploads)
- [Malware scanning](#malware-scanning)
- [Active Storage analyzer, Shrine, CarrierWave, Rack](#active-storage-analyzer-shrine-carrierwave-rack)
- [Command line](#command-line)
- [Protecting the server from large files](#protecting-the-server-from-large-files)
- [Policy options](#policy-options)

### Quick start

```ruby
ALLOWED_TYPES = %w[application/pdf image/png image/jpeg text/csv].freeze

result = UploadInspector.check(params[:file], allowed_types: ALLOWED_TYPES)

if result.safe?
  # store the file
else
  render json: { error: result.message }, status: :unprocessable_entity
end
```

Every call returns a `Result` and never raises on a hostile file:

| Method | Value |
|---|---|
| `safe?` | `true` when the file is accepted |
| `reason` | why it was rejected, e.g. `:pdf_active_content`, `:extension_mismatch` (`nil` when safe) |
| `message` | end-user message for the reason, e.g. `"is password-protected"` (`nil` when safe) |
| `detail` | technical hint for logs, not for end users |
| `detected_type` | the real MIME type, e.g. `"application/pdf"` |
| `would_reject` | in `mode: :report`, the reason the file would have been rejected (`nil` otherwise) |
| `sanitized_path` | where `sanitize` wrote the cleaned file (`nil` otherwise), see [Sanitizing uploads](#sanitizing-uploads-cdr) |
| `links` | web/mail links found in a PDF, Office, OpenDocument, RTF or SVG file (at most 100), e.g. to check them against Safe Browsing or URLhaus; also set on rejected files |

Only types in `allowed_types` are accepted (default: PDF only). See [What it checks](#what-it-checks)
for the types that get a structural check.

### What you can pass in

`check` takes the upload object itself. Rails/Rack uploads and Active Storage carry the
client-supplied name; anything else needs `filename:` (its extension must match the content).

```ruby
# Controller upload (ActionDispatch::Http::UploadedFile)
UploadInspector.check(params[:file], allowed_types: ALLOWED_TYPES)

# Active Storage attachment or blob (downloaded to a temp file first)
UploadInspector.check(contract.document, allowed_types: ALLOWED_TYPES)

# Path, File, Tempfile, StringIO or any IO
UploadInspector.check("/tmp/upload.bin", filename: "report.pdf", allowed_types: ALLOWED_TYPES)
UploadInspector.check(io, filename: "report.pdf", allowed_types: ALLOWED_TYPES)
```

Inspection takes up to `timeout` (60 s by default): check large files in a background job.

### Rails validator and job

Both load on first use; the gem does not depend on Rails.

```ruby
class Contract < ApplicationRecord
  has_one_attached :document

  # Checks files uploaded with this request, before save. Keep it to small files.
  validates :document, upload_inspector: { allowed_types: ALLOWED_TYPES }
end
```

The error type is the rejection reason (`errors.details` shows `{ error: :pdf_active_content }`),
the message comes from `result.message`. The validator covers `UploadedFile`s and
`attach(io:, filename:)`. Blobs already in storage (direct uploads, signed blob ids) are skipped,
and form strings are never read as server paths. Check those with the job:

```ruby
# After save, the file is in storage. Unsafe attachments are purged.
UploadInspector::InspectJob.perform_later(contract, "document", allowed_types: ALLOWED_TYPES)

# React to a rejection: subclass and override on_unsafe (called after the purge).
class InspectUploadJob < UploadInspector::InspectJob
  def on_unsafe(record, name, attachment, result)
    UploadMailer.rejected(record, attachment.filename.to_s, result.message).deliver_later
  end
end
```

Pass `purge: false` to keep unsafe files. Options are the same keywords as `check`.

### Presets

`UploadInspector::Presets` holds frozen `allowed_types` lists of verified types, to combine freely.
The default stays PDF only.

| Preset | Types |
|---|---|
| `PDF` | PDF |
| `OFFICE` | docx, xlsx, pptx |
| `DOCUMENTS` | `PDF` + `OFFICE` |
| `IMAGES` | PNG, JPEG, GIF, WebP, HEIC, HEIF, AVIF |
| `SVG` | SVG |
| `MEDIA` | MP4, QuickTime |
| `TEXT` | plain text, CSV, TSV |

```ruby
UploadInspector.check(file, allowed_types: UploadInspector::Presets::IMAGES + UploadInspector::Presets::DOCUMENTS)
```

### Shadow mode and instrumentation

To roll out on a live app, measure first: `mode: :report` runs every check but always accepts,
and sets `result.would_reject` to the reason it would have rejected. The validator never adds an
error and the job never purges.

```ruby
validates :document, upload_inspector: { allowed_types: ALLOWED_TYPES, mode: :report }
```

When ActiveSupport is loaded, every `check` / `check_s3` publishes `check.upload_inspector`
(the event's `duration` is the check time):

```ruby
ActiveSupport::Notifications.subscribe("check.upload_inspector") do |event|
  # event.payload: { mode:, reason:, would_reject:, detected_type:, filename_ext:, size: }
  rejected = event.payload[:reason] || event.payload[:would_reject]
  Rails.logger.info("upload_inspector #{rejected || 'safe'} #{event.payload[:filename_ext]} #{event.duration.round}ms")
end
```

`sanitize` publishes `sanitize.upload_inspector` with `{ reason:, detected_type:, filename_ext:, size: }`.

### Serving uploads safely

A checked file can still be dangerous if the app serves it so a browser renders it as a page.

- Serve user files from a separate domain (e.g. `usercontent.example.com` or the S3/CDN domain),
  never from the app's own origin, so a rendered file cannot read the app's cookies.
- Send `Content-Disposition: attachment` (download, not render) except for raster images and
  video, and always `X-Content-Type-Options: nosniff`. A strict CSP with `sandbox` blocks scripts
  if a file is rendered anyway. Keep SVG and PDF as attachments: browsers run SVG script when the
  SVG is opened directly, and Chrome refuses to show PDFs under a `sandbox` CSP.
- Never reuse the client's name as is. `UploadInspector.safe_filename(name, detected_type:)`
  drops the path, control and bidi characters, inner dots (`x.php.jpg` → `x_php.jpg`) and Windows
  reserved names, caps it at 255 bytes, and takes the extension from the detected type.

`safe_headers` builds those headers (`inline: true` is honoured for raster images and video only):

```ruby
result = UploadInspector.check(path, filename: name, allowed_types: ALLOWED_TYPES)
response.headers.merge!(UploadInspector.safe_headers(result, filename: name, inline: true))
# Content-Type (application/octet-stream unless safe), Content-Disposition,
# X-Content-Type-Options: nosniff, Content-Security-Policy: default-src 'none'; ...; sandbox
```

Active Storage serves only `content_types_allowed_inline` inline and forces
`content_types_to_serve_as_binary` (HTML, SVG, ...) to download; keep SVG and text in the latter.
For S3, set the headers on the presigned GET:

```ruby
s3_object.presigned_url(:get, response_content_disposition: "attachment; filename=\"#{safe_name}\"",
                              response_content_type: result.detected_type)
```

### Sanitizing uploads (CDR)

`check` accepts or rejects. `sanitize` checks the upload, writes a new file holding only the parts
known to be safe (content disarm and reconstruction), checks that file again and only then moves
it to `to:`. Payloads hidden where `check` does not look (a `<?php` in a JPEG comment, a zip in an
MP4 `free` box) are gone, and so is private metadata such as GPS coordinates. When the upload or
the cleaned file is rejected, nothing is written. It takes the same keywords as `check` (no `mode:`).

```ruby
result = UploadInspector.sanitize(params[:file], to: clean_path, allowed_types: UploadInspector::Presets::IMAGES)
if result.safe?
  store(result.sanitized_path) # == clean_path
else
  render json: { error: result.message }, status: :unprocessable_entity
end
```

| Format | Kept | Dropped |
|---|---|---|
| PNG | IHDR, PLTE, IDAT (merged into one), IEND, tRNS, gAMA, cHRM, sRGB, iCCP, pHYs, APNG frames | text chunks, eXIf, unknown chunks |
| JPEG | frame, tables, scans, JFIF APP0, ICC profile, Adobe APP14 (CMYK colors) | EXIF/XMP (APP1), comments, other APP segments, extra images (MPF: primary image kept) |
| GIF | header, color tables, frames, frame control, loop count | comments, plain text, other application extensions (XMP) |
| WebP | VP8, VP8L, VP8X (flags fixed), ALPH, ANIM, ANMF, ICCP | EXIF, XMP, unknown chunks |
| HEIC / HEIF / AVIF / MP4 / QuickTime | the boxes needed to play the file | other top-level boxes (`free`, `skip`, `uuid`...), user data and metadata in `moov` and its tracks, Exif/XMP items: zero-filled in place so no offset moves, or removed at the end of the file |
| SVG | allowlisted elements and attributes (shapes, text, gradients, patterns, masks, filters, `<style>`, `<a>`, `<title>`/`<desc>`, SMIL animation of kept attributes), re-escaped, UTF-8 | comments, processing instructions, DOCTYPE, `<metadata>`, unknown elements and attributes |
| CSV / TSV / TXT | the text as is | nothing, unless `neutralize_csv_formulas: true` |

Color profiles are kept (dropping them shifts the colors of wide-gamut photos) only when they
are structurally valid ICC profiles of at most 1 MB; their tag data is copied as is.

Other types (PDF, Office, zip...) are rejected as `:sanitize_unsupported`. Options:

- `keep_orientation: true` keeps the JPEG EXIF Orientation tag (and nothing else from EXIF), so
  photos are not shown rotated.
- `neutralize_csv_formulas: true` accepts CSV/TSV formula cells and writes them with a leading
  `'` (`=HYPERLINK(...)` → `'=HYPERLINK(...)`), so spreadsheets show them as text.
- `reencode: true` decodes PNG, JPEG, GIF, WebP, HEIC and AVIF with libvips and encodes new
  files: only the pixels survive, so this also removes data hidden in pixel or entropy-coded data.
  Needs the [`ruby-vips`](https://github.com/libvips/ruby-vips) gem and libvips (with libheif
  encoders for HEIC/AVIF), which this gem does not depend on; without them only `reencode: true`
  raises `ArgumentError`. Metadata is stripped, colors are converted to sRGB, and with
  `keep_orientation: true` the rotation is applied to the pixels. Every frame of an animation
  counts toward `max_image_pixels`.

Kept parts are copied byte for byte: pixel data and video samples are not decoded unless
`reencode: true`, and data inside an MP4 `mdat` that no sample refers to is not removed.

### Error messages

`result.message` gives an end-user message for the reason ("is password-protected", "does not
match its file extension", ...). Translate or override any of them under
`upload_inspector.errors.<reason>`, with `upload_inspector.errors.default` as the fallback:

```yaml
vi:
  upload_inspector:
    errors:
      default: "chứa nội dung không được phép"
      too_large: "quá lớn"
```

### S3 (presigned URL uploads)

Files uploaded straight to S3 never pass through the app, and the browser chose their
Content-Type and size. `check_s3` reads the size with `HeadObject` (oversized objects are
rejected without downloading), downloads the object pinned to that ETag, and inspects the bytes.
`client` is any `Aws::S3::Client` (aws-sdk-s3 is not a dependency of this gem).

```ruby
s3 = Aws::S3::Client.new

result = UploadInspector.check_s3(
  client: s3,
  bucket: "uploads",
  key: "incoming/abc/report.pdf",
  filename: "report.pdf",  # optional, defaults to the key basename
  version_id: nil,         # optional, pin a version on versioned buckets
  allowed_types: ALLOWED_TYPES,
)

s3.delete_object(bucket: "uploads", key: "incoming/abc/report.pdf") unless result.safe?
```

S3 errors (missing key, access denied, network) raise, so a job retries rather than
deleting a file over an outage. Upload to a quarantine prefix nothing serves, and move the object
to its final key only once it is safe: a presigned URL can overwrite the object after the check
until it expires (use `copy_object` with `copy_source_if_match` and the checked ETag).

### Malware scanning

Pass a `scanner:` to `check` / `check_s3` / `sanitize` (and the validator) to scan files the
structural check accepted, in the same call. Rejected files are not scanned; `sanitize` scans the
cleaned copy.

```ruby
clamav = UploadInspector::Scanners::ClamAV.new(host: "clamav", port: 3310, timeout: 30)
# or the local Unix socket:            ClamAV.new(socket: "/var/run/clamav/clamd.ctl")
# or any command judged by exit code:  Scanners::Command.new("clamdscan", "--no-summary", "--fdpass")

result = UploadInspector.check(params[:file], allowed_types: ALLOWED_TYPES, scanner: clamav)
result.reason # => :malware_detected, result.detail # => "Eicar-Test-Signature"

validates :document, upload_inspector: { allowed_types: ALLOWED_TYPES, scanner: CLAMAV }
```

- `:malware_detected`: the scanner found something; `detail` is the signature name.
- `:scanner_failed`: it could not scan (clamd down, timeout, file over `max_stream`). Fail-closed:
  the file is rejected unless you pass `scanner_fail_open: true`.
- The scan runs in your process after the sandboxed check (it needs a socket), bounded by the
  adapter's `timeout`. Keep `max_stream` (default 25 MB) at or below clamd's `StreamMaxLength`:
  larger files are `:scanner_failed` rather than half-scanned. Big files belong in a job.
- `ClamAV` speaks clamd's `INSTREAM` protocol with the stdlib `socket`. `Command` runs a binary
  without a shell, appending the file path: exit 0 clean, 1 infected, anything else an error.
- Any object with `scan(path)` returning `:clean` or `[:infected, signature]` (raising when it
  cannot scan) works as a scanner.
- With ActiveSupport loaded, each scan publishes `scan.upload_inspector` with
  `{ scanner:, reason:, detail: }`.

`InspectJob` arguments must be serializable, so subclass it and override `scanner`. When the
scanner fails, the job still handles the other attachments, keeps that one and then raises
`UploadInspector::Scanners::Error` instead of purging it. Keep `max_file_size` at or below the
scanner's `max_stream`: a larger file is then rejected (and purged) as `:too_large` rather than
retried until the job gives up.

```ruby
class InspectUploadJob < UploadInspector::InspectJob
  retry_on UploadInspector::Scanners::Error, wait: :polynomially_longer, attempts: 10
  def scanner = UploadInspector::Scanners::ClamAV.new(host: "clamav")
end
```

For S3 buckets with [GuardDuty Malware Protection for S3](https://docs.aws.amazon.com/guardduty/latest/ug/gdu-malware-protection-s3.html),
`check_s3(require_guardduty_tag: true)` reads its `GuardDutyMalwareScanStatus` object tag first
(needs `s3:GetObjectTagging`): `THREATS_FOUND` is `:malware_detected` without downloading,
`NO_THREATS_FOUND` goes on to the inspection, other statuses are `:scanner_failed`. While the tag
is missing (scan not finished) it raises `UploadInspector::Scanners::Pending`, so the job retries.

The tag is only a verdict if the uploader cannot write it: a presigned POST policy or any
principal with `s3:PutObjectTagging` could tag its own object `NO_THREATS_FOUND`. Deny setting
that tag key to everyone but GuardDuty's role in the bucket policy (or pass a `scanner:` too):

```json
{
  "Sid": "OnlyGuardDutySetsScanStatus",
  "Effect": "Deny",
  "Principal": "*",
  "Action": ["s3:PutObject", "s3:PutObjectTagging", "s3:PutObjectVersionTagging"],
  "Resource": "arn:aws:s3:::uploads/*",
  "Condition": {
    "ForAnyValue:StringEquals": { "s3:RequestObjectTagKeys": "GuardDutyMalwareScanStatus" },
    "StringNotEquals": { "aws:PrincipalArn": "arn:aws:iam::123456789012:role/GuardDutyS3MalwareProtectionRole" }
  }
}
```

### Active Storage analyzer, Shrine, CarrierWave, Rack

Each loads only when you use it; the gem depends on none of these libraries. Options are the
same keywords as `check` (Policy options, `sandbox:`, `scanner:`, `mode:`).

**Active Storage analyzer**: inspects every blob once uploaded, direct uploads included (the
validator never sees those), and records the verdict in `blob.metadata`. To act on unsafe blobs,
subclass it, override `on_unsafe(result)` and register the subclass instead.

```ruby
# config/initializers/upload_inspector.rb
UploadInspector::ActiveStorageAnalyzer.options = { allowed_types: ALLOWED_TYPES }
Rails.application.config.active_storage.analyzers.prepend UploadInspector::ActiveStorageAnalyzer

blob.metadata[:upload_inspector] # => { "safe" => false, "reason" => "pdf_active_content", "detected_type" => "application/pdf" }
UploadInspector::ActiveStorageAnalyzer.safe?(blob) # => false
```

Decide with `safe?`, not the raw metadata: direct uploads let the client send blob metadata, so
an `upload_inspector` key may be the client's own until the analyzer overwrites it. `safe?` is
true only once the blob is analyzed (a flag Rails does not accept from clients) with a safe
verdict; pending, failed or missing means unsafe. Blobs analyzed before you registered the
analyzer may still carry a client-sent verdict: re-analyze them (`blob.analyze`).

```ruby
class FlagUnsafeUploads < UploadInspector::ActiveStorageAnalyzer
  def on_unsafe(result) # runs before the metadata is saved; `blob` is the blob
    blob.attachments.each(&:purge_later)
  end
end
```

Active Storage runs one analyzer per blob; this one merges in the metadata of the analyzer that
would have run otherwise (image width/height, video duration).

**Shrine** (3.x): validation errors join your `Attacher.validate` block; `sanitize: true` stores
a cleaned copy on promote (types that cannot be cleaned, like PDF, are stored as checked).

```ruby
class DocumentUploader < Shrine
  plugin :upload_inspector, allowed_types: ALLOWED_TYPES, sanitize: true
end
attacher.errors                  # => ["does not match its file extension"]
attacher.upload_inspector_result # => the Result
```

**CarrierWave** (3.x): unsafe files raise `CarrierWave::IntegrityError` when cached, before any
processing, so the model gets a validation error with the rejection message.

```ruby
class DocumentUploader < CarrierWave::Uploader::Base
  include UploadInspector::CarrierWave
  def upload_inspector_options = { allowed_types: ALLOWED_TYPES }
  process :upload_inspector_sanitize # optional: keep a cleaned copy
end
```

**Rack middleware** (any Rack app): checks every file of multipart requests to `paths` and
answers `422` with `{ "error": message, "reason": reason, "field": "doc[file]" }` when one is
unsafe. The check runs inside the request: list only upload endpoints taking small files and
check large ones in a job.

```ruby
use UploadInspector::Rack, paths: [%r{\A/uploads}], allowed_types: ALLOWED_TYPES
```

`paths` are Strings (exact) or Regexps, matched against the path both as sent and as a router
reads it (percent-decoded, repeated and trailing slashes removed), so `//uploads` or
`/%75ploads/` do not slip past.

**Sinatra / Hanami / Roda** need no adapter: call `check` on the uploaded tempfile.

```ruby
# Sinatra
post "/uploads" do
  upload = params[:file] # { filename:, tempfile:, ... }
  result = UploadInspector.check(upload[:tempfile], filename: upload[:filename], allowed_types: ALLOWED_TYPES)
  halt 422, result.message unless result.safe?
end

# Hanami action
def handle(request, response)
  upload = request.params[:file]
  result = UploadInspector.check(upload[:tempfile], filename: upload[:filename], allowed_types: ALLOWED_TYPES)
  halt 422, result.message unless result.safe?
end
```

### Command line

`upload_inspector` checks files, re-scans a directory of stored uploads (after an incident, or
when tightening the policy), or sanitizes a file. Exit status: 0 all safe, 1 something unsafe,
2 usage or runtime error.

```sh
upload_inspector check report.pdf photo.jpg --types documents,images
upload_inspector scan public/uploads --recursive --types pdf,images --json > verdicts.jsonl
upload_inspector sanitize photo.jpg --out clean.jpg --types images
upload_inspector check file.docx --types office --clamav /var/run/clamav/clamd.ctl   # or --clamav clamav:3310
```

- `--types` takes MIME types and preset names (`pdf`, `office`, `documents`, `images`, `svg`,
  `media`, `text`); the default is PDF only, as for `check`.
- `--json` prints one JSON object per file and line, as soon as it is checked.
- The name checked against the content is the file's basename. Stores that name files by a
  random key without extension (Active Storage's disk service) are better checked through the
  app: `blob.open` with `blob.filename`, or `InspectJob`.
- `scan` skips symlinks. `--no-sandbox` inspects in the CLI process.

### Protecting the server from large files

No input is read into Ruby memory: S3 objects and IO are streamed to a temp file, Rails uploads
are already on disk (Rack buffers them), and inspection runs in the memory-limited sandbox.
Formats like zip, Office and PDF need random access, so the whole file must be on disk. What is left
to bound is disk and time:

- **Size before download.** `check_s3` rejects from `HeadObject`, Active Storage from
  `byte_size`, IO stops at `max_file_size + 1` bytes. Set `max_file_size` to what you actually
  accept, not the 500 MB default.
- **Refuse oversized uploads at the source.** Rails: cap the request body in the web server
  (nginx `client_max_body_size`). S3: hand out a presigned **POST** with a size range; a presigned
  PUT cannot enforce one.

  ```ruby
  post = Aws::S3::Bucket.new("uploads").presigned_post(
    key: "incoming/#{SecureRandom.uuid}/${filename}",
    content_length_range: 1..(20 * 1024 * 1024),
    expires: Time.now + 300,
  )
  ```
- **Download time.** `timeout` covers inspection only, not the S3 download. Bound the download
  on the client you pass in, e.g. `Aws::S3::Client.new(http_open_timeout: 5, http_read_timeout: 30, retry_limit: 2)`.
- **Disk under load.** Each concurrent check can use up to `max_file_size` of temp disk (plus
  extracted zip members, up to `max_zip_total_size`). Run checks in a job queue with capped
  concurrency and size the temp volume for `concurrency × max_file_size`.

### Policy options

| Option | Default |
|---|---|
| `allowed_types` | `['application/pdf']` |
| `allow_unverifiable` | `[]` |
| `max_file_size` | 500 MB |
| `max_zip_entries` / `max_zip_entry_size` / `max_zip_total_size` | 5 000 / 200 MB / 1 GB |
| `max_compression_ratio` | 100 (entries ≥ 1 MB) |
| `max_inflate_size` | 50 MB per PDF object stream / OOXML or OpenDocument XML part / SVG, text or RTF file / legacy Office main stream |
| `max_image_pixels` | 100 000 000 (declared width × height) |
| `allow_csv_formulas` | `false` |
| `allow_text_markup` | `false` |
| `pdf_links` | `:allow` (`:reject` rejects PDFs with any link as `:pdf_link`) |
| `timeout` / `cpu_limit` | 60 s / 60 s |
| `memory_limit` | 1 GB (`RLIMIT_DATA`, Linux only) |

## Sandbox

By default (`sandbox: true`) inspection (and sanitizing) runs in a child Ruby process with CPU, memory (Linux) and
wall-clock limits. A crash, hang or memory blow-up kills only the child and yields a rejection
(`:timeout`, `:resource_limit`, `:inspection_failed`), so web/job workers are unaffected.
The child's temp files live in a directory the parent removes, also when the child is killed.
It is resource isolation, not a security boundary (same OS user).

## Development

Tests build hostile-shaped samples in memory (no real malware). The scanner tests write the
EICAR antivirus test string to temp files. Run them in a container or CI rather than on a
workstation with endpoint AV:

```sh
docker run --rm -v "$PWD":/src:ro ruby:3.3 \
  bash -c 'cp -r /src /app && cd /app && rm -rf vendor .bundle && bundle install && bundle exec rake test'
```

CI runs the suite on Ruby 3.2 / 3.3 / 3.4 against rubyzip 2.3 and 3.x, and the sanitize tests
against real decoders (libvips, ImageMagick) and the ClamAV adapter against a real clamd
(`CLAMD_HOST=localhost` with `docker run -p 3310:3310 clamav/clamav:stable`). Locally they are skipped without those tools; for
`reencode` run `bundle config set --local with vips` (needs libvips). The Rails helper tests
use `activemodel` / `activejob` from the Gemfile (development only). The integration tests
(Shrine, CarrierWave, Active Storage, Rack) need `bundle config set --local with integration`.

`test/sample_virus_malware.rb` is the hostile-sample corpus: every attack shape with its expected
verdict, plus known gaps (skipped until fixed). `bundle exec rake samples[DIR]` writes the inert
samples to disk (default `tmp/samples`) to cross-check against real readers or other scanners.

## License

MIT
