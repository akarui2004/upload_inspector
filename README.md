# upload_inspector

Fail-closed structural inspection of untrusted uploaded files for any Ruby or Rails app.
Checks a path, a Rails upload, an Active Storage attachment, any IO, or an S3 object uploaded
through a presigned URL.

A file is accepted only when its structure is proven to match a known-safe shape. Anything unknown,
unparsable, encrypted, oversized, or erroring is rejected. Pure Ruby (`marcel`, `rubyzip`), no AV engine,
no native parsers, nothing is rendered or executed.

> **Not an antivirus.** It blocks structural attack vectors (disguised executables, macros, PDF
> JavaScript, OLE objects, remote templates, DDE, zip bombs, image polyglots, scripted SVG). It does not detect malware signatures or
> exploits hidden inside otherwise valid content. Pair it with an AV scanner (e.g. Amazon GuardDuty
> Malware Protection for S3, endpoint AV) when you need that.

## What it checks

| Format | Checks |
|---|---|
| All | real type by magic bytes (Marcel) must be allowlisted; file extension must agree with content; size limit |
| PDF (and PDF-based `.ai`) | rejects `/JavaScript /JS /Launch /EmbeddedFile(s) /EF /FileAttachment /Filespec /Collection /RichMedia /XFA /SubmitForm /ImportData /GoToR /GoToE /Rendition`, hex-escaped spellings included, also inside compressed object streams (located by `/ObjStm` or `/First` and parsed with a real PDF lexer, so comments, strings and fake headers cannot hide them); rejects risky parsers (`/JBIG2Decode`, 3D/U3D/PRC, PostScript XObjects), URI links other than http(s)/mailto/relative (`file:`, UNC, `javascript:`, indirect values), encrypted PDFs and unsupported object-stream filters |
| docx / pptx / xlsx | every part name must match an allowlist, and no check trusts a part's path (Office finds parts through content types and relationships): every part is inspected as XML or proven not to be XML, every XML part gets every check, and only relationship types known to be passive are accepted. Rejects VBA, `embeddings/`, `activeX/`, macro sheets, external data (connections, query tables, external/DDE/OLE links, Power Query) by part name, content type, relationship type and element, macro content types, DTDs, external relationships other than http(s)/mailto hyperlinks, Word DDE/INCLUDE(TEXT/PICTURE)/IMPORT/LINK/QUOTE/DATABASE/MACROBUTTON fields, PowerPoint program/macro actions, Excel DDE formulas and defined names, malformed XML, XML that is not UTF-8/ASCII/Latin-1; checks run on entity-decoded text and CDATA |
| PNG / JPEG / GIF / WebP | container walked block by block (nothing is decoded): every length must stay inside the file, declared dimensions within `max_image_pixels`, and nothing may follow the end of the image (appended scripts or archives). JPEG files holding several images back to back (HDR gain maps, MPF) are accepted; other trailers (motion-photo video, vendor data) are rejected, re-encode those |
| SVG | static only: rejects script elements, `on*` handlers, `javascript:`/`data:` links (also set through animation), XHTML/MathML content, stylesheet processing instructions, DTDs other than the standard W3C DOCTYPE, CSS `@import`/escapes, and any reference outside the file (`href`, `src`, CSS `url()`) except `#fragment`, embedded `data:image/png|jpeg|gif|webp` and http(s)/mailto links on `<a>` |
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

Images and SVG are verified when their MIME type is in `allowed_types`
(`image/png image/jpeg image/gif image/webp image/svg+xml`). Listing them in `allow_unverifiable`
instead skips these checks.

## Install

```ruby
gem 'upload_inspector'
```

Requires Ruby >= 3.2.

## Usage

```ruby
result = UploadInspector.check(
  '/tmp/upload.pdf',
  filename: 'design.pdf',                      # client-supplied name
  allowed_types: %w[application/pdf application/zip],
)

result.safe?          # => true / false
result.reason         # => :pdf_active_content, :pdf_unsafe_uri, :type_not_allowed, ... (nil when safe)
result.detail         # => human-readable hint
result.detected_type  # => "application/pdf"
```

### Rails uploads, files and IO

`check` takes a path or the upload object itself. Rails/Rack uploads and Active Storage carry the
client-supplied name; a path, `File`, `Tempfile` or plain IO needs `filename:`.

```ruby
# Controller: ActionDispatch::Http::UploadedFile (name from original_filename)
result = UploadInspector.check(params[:file], allowed_types: ALLOWED_TYPES)

# Active Storage attachment or blob (downloaded to a temp file for the check)
result = UploadInspector.check(record.document, allowed_types: ALLOWED_TYPES)
record.document.purge_later unless result.safe?

# File / Tempfile / StringIO (IO is copied to a temp file, at most max_file_size + 1 bytes)
result = UploadInspector.check(io, filename: "report.pdf", allowed_types: ALLOWED_TYPES)
```

Run it in a background job for large files.

### S3 (presigned URL uploads)

Files uploaded straight to S3 never pass through the app, and the browser chose their
Content-Type and size. `check_s3` reads the size with `HeadObject` (oversized objects are
rejected without downloading), downloads the object pinned to that ETag, and inspects the bytes.
`client` is any `Aws::S3::Client` (aws-sdk-s3 is not a dependency of this gem).

```ruby
result = UploadInspector.check_s3(
  client: Aws::S3::Client.new, bucket: "uploads", key: "incoming/abc/report.pdf",
  filename: "report.pdf",   # defaults to the key basename
  version_id: nil,          # pin a version on versioned buckets
  allowed_types: ALLOWED_TYPES,
)
s3.delete_object(bucket: "uploads", key: "incoming/abc/report.pdf") unless result.safe?
```

S3 errors (missing key, access denied, network) raise, so a job retries rather than
deleting a file over an outage. Upload to a quarantine prefix nothing serves, and move the object
to its final key only once it is safe: a presigned URL can overwrite the object after the check
until it expires (use `copy_object` with `copy_source_if_match` and the checked ETag).

### Policy options

| Option | Default |
|---|---|
| `allowed_types` | `['application/pdf']` |
| `allow_unverifiable` | `[]` |
| `max_file_size` | 500 MB |
| `max_zip_entries` / `max_zip_entry_size` / `max_zip_total_size` | 5 000 / 200 MB / 1 GB |
| `max_compression_ratio` | 100 (entries ≥ 1 MB) |
| `max_inflate_size` | 50 MB per PDF object stream / OOXML XML part / SVG file |
| `max_image_pixels` | 100 000 000 (declared width × height) |
| `timeout` / `cpu_limit` | 60 s / 60 s |
| `memory_limit` | 1 GB (`RLIMIT_DATA`, Linux only) |

## Sandbox

By default (`sandbox: true`) inspection runs in a child Ruby process with CPU, memory (Linux) and
wall-clock limits. A crash, hang or memory blow-up kills only the child and yields a rejection
(`:timeout`, `:resource_limit`, `:inspection_failed`), so web/job workers are unaffected.
The child's temp files live in a directory the parent removes, also when the child is killed.
It is resource isolation, not a security boundary (same OS user).

## Development

Tests build hostile-shaped samples in memory (no real malware, no AV test signatures).
Run them in a container or CI rather than on a workstation with endpoint AV:

```sh
docker run --rm -v "$PWD":/src:ro ruby:3.3-slim \
  bash -c 'cp -r /src /app && cd /app && bundle install && bundle exec rake test'
```

CI runs the suite on Ruby 3.2 / 3.3 / 3.4 against rubyzip 2.3 and 3.x.

`test/sample_virus_malware.rb` is the hostile-sample corpus: every attack shape with its expected
verdict, plus known gaps (skipped until fixed). `bundle exec rake samples[DIR]` writes the inert
samples to disk (default `tmp/samples`) to cross-check against real readers or other scanners.

### Releasing

1. Bump `lib/upload_inspector/version.rb`, update `CHANGELOG.md`, merge to `main`.
2. Actions → **Release** → *Run workflow*. It runs CI, tags `vX.Y.Z` and publishes via
   rubygems.org Trusted Publishing.

## License

MIT
