# upload_inspector

Fail-closed structural inspection of untrusted uploaded files for any Ruby or Rails app.

A file is accepted only when its structure is proven to match a known-safe shape. Anything unknown,
unparsable, encrypted, oversized, or erroring is rejected. Pure Ruby (`marcel`, `rubyzip`), no AV engine,
no native parsers, nothing is rendered or executed.

> **Not an antivirus.** It blocks structural attack vectors (disguised executables, macros, PDF
> JavaScript, OLE objects, remote templates, DDE, zip bombs). It does not detect malware signatures or
> exploits hidden inside otherwise valid content. Pair it with an AV scanner (e.g. Amazon GuardDuty
> Malware Protection for S3, endpoint AV) when you need that.

## What it checks

| Format | Checks |
|---|---|
| All | real type by magic bytes (Marcel) must be allowlisted; file extension must agree with content; size limit |
| PDF (and PDF-based `.ai`) | rejects `/JavaScript /JS /Launch /EmbeddedFile(s) /RichMedia /XFA /SubmitForm /ImportData /GoToR /GoToE /Rendition`, hex-escaped spellings included, also inside compressed object streams (located by `/ObjStm` or `/First` and parsed with a real PDF lexer, so comments, strings and fake headers cannot hide them); rejects risky parsers (`/JBIG2Decode`, 3D/U3D/PRC, PostScript XObjects), URI links other than http(s)/mailto/relative (`file:`, UNC, `javascript:`, indirect values), encrypted PDFs and unsupported object-stream filters |
| docx / pptx / xlsx | every part name must match an allowlist; rejects VBA, `embeddings/`, `activeX/`, `externalLinks/`, macro sheets, external data connections (`connections.xml`, `queryTables/`, Power Query), macro content types, DTDs, external relationships other than http(s)/mailto hyperlinks, relationships of macro/OLE/ActiveX/altChunk type, Word DDE/INCLUDE(TEXT/PICTURE)/IMPORT/LINK/QUOTE/DATABASE/MACROBUTTON fields, PowerPoint program/macro actions, Excel DDE formulas and defined names, non-UTF-8 XML; checks run on entity-decoded text and CDATA |
| zip | path traversal, symlinks, encrypted entries, duplicates, entry/total size and compression-ratio limits, nested archives; every member extracted (bounded) and inspected with the same policy |
| Others | rejected unless listed in `allow_unverifiable` (type + extension check only) |

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

### Rails / Active Storage

```ruby
result = blob.open do |file|
  UploadInspector.check(file.path, filename: blob.filename.to_s, allowed_types: ALLOWED_TYPES)
end
blob.purge_later unless result.safe?
```

Run it in a background job for large files.

### Policy options

| Option | Default |
|---|---|
| `allowed_types` | `['application/pdf']` |
| `allow_unverifiable` | `[]` |
| `max_file_size` | 500 MB |
| `max_zip_entries` / `max_zip_entry_size` / `max_zip_total_size` | 5 000 / 200 MB / 1 GB |
| `max_compression_ratio` | 100 (entries ≥ 1 MB) |
| `max_inflate_size` | 50 MB per PDF object stream / OOXML XML part |
| `timeout` / `cpu_limit` | 60 s / 60 s |
| `memory_limit` | 1 GB (`RLIMIT_DATA`, Linux only) |

## Sandbox

By default (`sandbox: true`) inspection runs in a child Ruby process with CPU, memory (Linux) and
wall-clock limits. A crash, hang or memory blow-up kills only the child and yields a rejection
(`:timeout`, `:resource_limit`, `:inspection_failed`), so web/job workers are unaffected.
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
