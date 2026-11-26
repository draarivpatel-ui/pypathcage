# Good first issues: framework adapters

These are concrete integration tasks for popular Python web and storage libraries. Each one should be a small module with tests that use temporary directories.

1. FastAPI UploadFile adapter: add `safe_extract_upload(upload: UploadFile, destination)` that spools the upload to a temporary file and calls `safe_extract_zip` or `safe_extract_tar` based on the content type.

2. Starlette multipart helper: accept a `UploadFile`, inspect before extraction, and map `PathCageError` to HTTP 400 with the typed code in the JSON body.

3. Django FileSystemStorage adapter: add a `SafeStorage` subclass whose `save()` calls `sanitize_filename` on the supplied name and rejects traversal before delegating to the parent class.

4. Django upload handler: add a handler that runs `inspect_zip` on uploaded archives during `file_complete()` and raises `SuspiciousFileOperation` on rejection.

5. Flask `request.files` helper: add `extract_request_archive(field_name, destination)` that selects the right extractor from the filename, falls back to content sniffing and enforces `ArchiveLimits` from app config.

6. aiofiles async extractor: add `async_safe_extract_zip` that performs inspection synchronously, then streams member bytes through `aiofiles` while reusing the same byte counting logic.

7. Tornado `HTTPFile` adapter: validate uploaded archives with `inspect_zip` or `inspect_tar` before moving them out of the request temporary directory.

8. Sanic request adapter: mirror the Flask helper with Sanic's `request.files` object and document the default limits.

9. 7z adapter: add a hook that lists 7z members with a trusted reader and feeds each name through `check_lexical` and containment checks before extraction.

10. RAR adapter: add a hook for `rarfile` archives that rejects link entries and enforces the same file count and total byte limits as the built-in extractors.

11. AWS S3 download adapter: add `extract_s3_archive(bucket, key, destination)` that streams the object to a temporary file, inspects it and extracts with limits derived from the object size.

12. Azure Blob adapter: mirror the S3 helper using an `azure-storage-blob` BlobClient and keep all temporary files inside a `TemporaryDirectory`.

13. Google Cloud Storage adapter: mirror the S3 helper using `google-cloud-storage` and expose the inspection report to the caller.

14. TUS protocol upload adapter: add a post-upload validation callback that inspects the assembled file before it is made available to application code.

15. CLI bulk inspector: extend `python3 -m pypathcage inspect` to accept a directory or a glob and print one JSON line per archive, continuing after rejections and exiting nonzero if any archive failed.

Every adapter should include at least one hostile fixture: a traversal member, an absolute member and a case-insensitive collision. Keep dependencies optional and import them inside the adapter module so the core package stays dependency free.
