kng_github_api <- function(path) {
  base <- getOption(
    "knhanesget.github_api_base",
    "https://api.github.com"
  )
  paste0(sub("/$", "", base), path)
}

kng_fetch_json <- function(url) {
  handle <- curl::new_handle(
    useragent = paste0("knhanesget/", utils::packageVersion("knhanesget")),
    httpheader = c(Accept = "application/vnd.github+json")
  )
  response <- curl::curl_fetch_memory(url, handle = handle)
  if (response$status_code != 200L) {
    stop(
      "Cannot read the knhanes release metadata (HTTP ",
      response$status_code,
      ").",
      call. = FALSE
    )
  }
  jsonlite::fromJSON(rawToChar(response$content), simplifyVector = FALSE)
}

kng_release_metadata <- function(version = "latest") {
  kng_scalar_character(version, "version")
  if (identical(trimws(version), "latest")) {
    path <- paste0(
      "/repos/", .kng_dist_owner, "/", .kng_dist_repo, "/releases/latest"
    )
  } else {
    version <- kng_normalize_version(version)
    path <- paste0(
      "/repos/", .kng_dist_owner, "/", .kng_dist_repo,
      "/releases/tags/v", version
    )
  }
  release <- kng_fetch_json(kng_github_api(path))
  tag <- release$tag_name %||% ""
  resolved_version <- kng_normalize_version(tag)
  asset_names <- vapply(release$assets, `[[`, character(1), "name")
  asset_urls <- vapply(
    release$assets,
    `[[`,
    character(1),
    "browser_download_url"
  )
  expected <- c(
    archive = paste0("knhanes_", resolved_version, ".tar.gz"),
    checksum = paste0("knhanes_", resolved_version, ".tar.gz.sha256"),
    signature = paste0("knhanes_", resolved_version, ".tar.gz.sig")
  )
  positions <- match(unname(expected), asset_names)
  names(positions) <- names(expected)
  if (anyNA(positions)) {
    stop(
      "Release v", resolved_version,
      " does not contain the archive, checksum, and signature assets.",
      call. = FALSE
    )
  }
  list(
    version = resolved_version,
    tag = paste0("v", resolved_version),
    archive_name = unname(expected[["archive"]]),
    archive_url = asset_urls[[positions[["archive"]]]],
    checksum_url = asset_urls[[positions[["checksum"]]]],
    signature_url = asset_urls[[positions[["signature"]]]],
    html_url = release$html_url %||% NA_character_
  )
}

`%||%` <- function(x, y) {
  if (is.null(x)) y else x
}

kng_download <- function(url, path, quiet = FALSE) {
  handle <- curl::new_handle(
    useragent = paste0("knhanesget/", utils::packageVersion("knhanesget"))
  )
  tryCatch(
    curl::curl_download(url, destfile = path, quiet = quiet, handle = handle),
    error = function(e) {
      stop("Download failed: ", conditionMessage(e), call. = FALSE)
    }
  )
  if (!file.exists(path) || file.info(path)$size <= 0) {
    stop("Downloaded release asset is empty: ", basename(path), call. = FALSE)
  }
  invisible(path)
}

kng_verify_archive <- function(archive, checksum_file, signature_file) {
  checksum_text <- trimws(readLines(checksum_file, n = 1L, warn = FALSE))
  expected <- tolower(strsplit(checksum_text, "[[:space:]]+", perl = TRUE)[[1L]][1L])
  if (!grepl("^[0-9a-f]{64}$", expected)) {
    stop("The release checksum file is invalid.", call. = FALSE)
  }
  archive_raw <- readBin(archive, what = "raw", n = file.info(archive)$size)
  actual <- sodium::bin2hex(sodium::sha256(archive_raw))
  if (!identical(actual, expected)) {
    stop("The downloaded knhanes archive failed SHA-256 verification.",
         call. = FALSE)
  }
  signature_hex <- tolower(trimws(readLines(
    signature_file,
    n = 1L,
    warn = FALSE
  )))
  signature <- tryCatch(
    sodium::hex2bin(signature_hex),
    error = function(e) NULL
  )
  if (is.null(signature) || length(signature) != 64L) {
    stop("The release signature file is invalid.", call. = FALSE)
  }
  public_key <- sodium::hex2bin(.kng_release_public_key_hex)
  verified <- tryCatch(
    sodium::sig_verify(archive_raw, signature, public_key),
    error = function(e) FALSE
  )
  if (!isTRUE(verified)) {
    stop("The downloaded knhanes archive signature is invalid.", call. = FALSE)
  }
  invisible(list(sha256 = actual, signature_verified = TRUE))
}
