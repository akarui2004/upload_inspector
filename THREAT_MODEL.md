# Threat model

`upload_inspector` decides whether an untrusted uploaded file has a structure known to be safe.
This page states what it defends against, what it does not, and what it assumes of the app.

## Attacker

Anyone who can upload a file: they control every byte, the file name, the declared
Content-Type and size (browser and presigned-URL uploads alike). They want the file stored and
later opened by a person, a browser or a server process where it does harm.

## In scope (rejected)

- **Disguised types**: content whose real type is not allowlisted, or whose extension names a
  different type than the content (an executable named `.pdf`, a PDF named `.zip`).
- **Active content inside allowed formats**: PDF JavaScript, launch actions, embedded files,
  risky parsers; Office macros, embedded objects, ActiveX, DDE and field codes, remote templates
  and external links; SVG script, event handlers and outside references; HTML/script tags in text
  files; CSV/TSV formulas that call functions or other programs.
- **Polyglots and appended data**: data after the end of an image or outside the box structure of
  HEIC/AVIF/MP4, part names and relationships Office would load that are not inspected.
- **Resource exhaustion**: zip bombs, oversized entries, huge declared image dimensions, deep
  nesting, files over the size limits. Inspection runs in a child process with CPU, memory
  (Linux) and wall-clock limits.
- **Hostile file names**: bidi overrides, control characters, executable extensions hidden before
  the last one (`shell.php.jpg`), path traversal inside zips.
- **Unknown or unparsable input**: anything the gem cannot prove safe is rejected (fail closed),
  including encrypted files.

## Out of scope (not detected)

- **Malware signatures and exploits in valid content**: a crafted font, image codec or media
  stream exploiting a reader bug, or a malicious executable inside an allowed type that the
  structure check cannot see. Pair the gem with an antivirus or malware scanner.
- **Data hidden inside an allowed structure** (steganography, a zip inside an MP4 `free` box,
  pixel data). It is inert unless another flaw extracts it; re-encoding removes it.
- **Phishing content**: links to http(s) sites and social-engineering text are allowed (PDF links that
  open with no click are rejected; `Result#links` lists the links found so the app can check them).
- **Types in `allow_unverifiable`**: only the real type and extension are checked.
- **The app's serving and storage**: see the assumptions below.

## Assumptions

- **The sandbox is resource isolation, not a security boundary.** The child runs as the same OS
  user. The gem never executes or renders file content and parses in pure Ruby, which keeps the
  risk of a parser bug low, but a Ruby/OS-level escape is not contained.
- **Files are served safely**: from a separate domain, as downloads except raster images and
  video, with `X-Content-Type-Options: nosniff` (see `UploadInspector.safe_headers` and the
  README section "Serving uploads safely"). A checked file served inline from the app's origin can
  still be misinterpreted by a browser.
- **The client's file name is not reused as is** for storage paths or headers
  (`UploadInspector.safe_filename`).
- **The checked bytes are the stored bytes**: check before the file can be replaced (quarantine
  prefix for S3, ETag-pinned copy), and re-check after any transformation.
- **Limits fit the app**: `max_file_size` and the other limits are set to what the app really
  accepts, and large files are checked in a background job.
- **Ruby, Marcel and rubyzip are kept up to date.**

## Known limitations

- Large PDFs can be rejected by chance when compressed data spells a blocked name (README,
  "Large PDFs can be rejected by chance").
- Known gaps are tracked as skipped samples in `test/sample_virus_malware.rb`.
