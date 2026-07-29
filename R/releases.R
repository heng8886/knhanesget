kng_github_api <- function(path) {
  base <- getOption(
    "knhanesget.github_api_base",
    "https://api.github.com"
  )
  paste0(sub("/$", "", base), path)
}

kng_release_source <- function() {
  source <- getOption("knhanesget.release_source", NULL)
  if (is.null(source)) {
    source <- Sys.getenv(
      "KNHANESGET_RELEASE_SOURCE",
      unset = .kng_default_release_source
    )
  }
  kng_scalar_character(source, "knhanesget release source")
  source <- tolower(trimws(source))
  if (!source %in% c("github", "server")) {
    stop(
      "knhanesget release source must be 'github' or 'server'.",
      call. = FALSE
    )
  }
  source
}

kng_server_base_url <- function() {
  base <- getOption("knhanesget.server_base_url", NULL)
  if (is.null(base)) {
    base <- Sys.getenv(
      "KNHANESGET_SERVER_BASE_URL",
      unset = .kng_default_server_base_url
    )
  }
  kng_scalar_character(base, "knhanesget server base URL")
  base <- sub("/+$", "", trimws(base))
  parsed <- tryCatch(
    curl::curl_parse_url(base),
    error = function(e) NULL
  )
  invalid <- is.null(parsed) ||
    !identical(parsed$scheme, "https") ||
    is.null(parsed$host) ||
    !nzchar(parsed$host) ||
    !is.null(parsed$user) ||
    !is.null(parsed$password) ||
    !is.null(parsed$fragment) ||
    length(parsed$params) > 0L
  if (invalid) {
    stop(
      "knhanesget server base URL must be an HTTPS URL without ",
      "credentials, query parameters, or a fragment.",
      call. = FALSE
    )
  }
  base
}

kng_server_url <- function(path) {
  kng_scalar_character(path, "server API path")
  paste0(kng_server_base_url(), "/", sub("^/+", "", path))
}

kng_server_request_json <- function(path,
                                    method = "GET",
                                    body = NULL,
                                    expected_status = 200L) {
  kng_scalar_character(method, "HTTP method")
  method <- toupper(trimws(method))
  headers <- c(Accept = "application/json")
  handle <- curl::new_handle(
    useragent = paste0("knhanesget/", utils::packageVersion("knhanesget")),
    customrequest = method,
    connecttimeout = 20L,
    timeout = 60L
  )
  curl::handle_setheaders(handle, .list = as.list(headers))
  if (!is.null(body)) {
    payload <- jsonlite::toJSON(
      body,
      auto_unbox = TRUE,
      null = "null",
      na = "null"
    )
    curl::handle_setheaders(
      handle,
      `Content-Type` = "application/json"
    )
    curl::handle_setopt(handle, postfields = payload)
  }
  response <- tryCatch(
    curl::curl_fetch_memory(kng_server_url(path), handle = handle),
    error = function(e) {
      stop(
        "Cannot reach the knhanes authorization server.",
        call. = FALSE
      )
    }
  )
  if (!response$status_code %in% as.integer(expected_status)) {
    stop(
      "The knhanes authorization server rejected the request (HTTP ",
      response$status_code,
      ").",
      call. = FALSE
    )
  }
  tryCatch(
    jsonlite::fromJSON(rawToChar(response$content), simplifyVector = FALSE),
    error = function(e) {
      stop(
        "The knhanes authorization server returned invalid JSON.",
        call. = FALSE
      )
    }
  )
}

kng_server_release_metadata <- function(version = "latest") {
  kng_scalar_character(version, "version")
  expected_artifacts <- c("archive", "checksum", "signature")
  if (identical(trimws(version), "latest")) {
    metadata <- kng_server_request_json("/v1/releases/latest")
    resolved_version <- kng_normalize_version(metadata$version %||% "")
    artifacts <- unlist(metadata$artifacts %||% list(), use.names = FALSE)
    if (!all(expected_artifacts %in% artifacts)) {
      stop(
        "The knhanes authorization server did not advertise all signed ",
        "release assets.",
        call. = FALSE
      )
    }
  } else {
    resolved_version <- kng_normalize_version(version)
  }
  archive_name <- paste0("knhanes_", resolved_version, ".tar.gz")
  artifact_base <- paste0(
    "/v1/releases/", resolved_version, "/artifacts/"
  )
  list(
    version = resolved_version,
    tag = paste0("v", resolved_version),
    archive_name = archive_name,
    archive_url = kng_server_url(paste0(artifact_base, "archive")),
    checksum_url = kng_server_url(paste0(artifact_base, "checksum")),
    signature_url = kng_server_url(paste0(artifact_base, "signature")),
    html_url = NA_character_,
    source = "server",
    access_token = NULL
  )
}

kng_selected_release_metadata <- function(version = "latest") {
  if (identical(kng_release_source(), "server")) {
    return(kng_server_release_metadata(version))
  }
  release <- kng_release_metadata(version)
  release$source <- "github"
  release$access_token <- NULL
  release
}

kng_local_license_code <- function(license_code = NULL) {
  if (!is.null(license_code)) {
    kng_scalar_character(license_code, "license_code")
    return(trimws(license_code))
  }
  path <- kng_license_path()
  if (!file.exists(path)) {
    stop(
      "A local knhanes license was not found. Obtain a license and pass ",
      "license_code, or activate knhanes before using the server source.",
      call. = FALSE
    )
  }
  value <- trimws(readLines(path, n = 1L, warn = FALSE))
  if (!nzchar(value)) {
    stop(
      "The local knhanes license file is empty. Obtain a valid license ",
      "before using the server source.",
      call. = FALSE
    )
  }
  value
}

kng_server_nonce <- function() {
  kng_base64url_encode(sodium::random(18L))
}

kng_authorize_server_release <- function(release, license_code = NULL) {
  if (!identical(release$source, "server")) {
    return(release)
  }
  code <- kng_local_license_code(license_code)
  request_code <- getToken(version = release$version, quiet = TRUE)
  session <- kng_server_request_json(
    "/v1/install-sessions",
    method = "POST",
    body = list(
      request_code = unname(request_code),
      license_code = unname(code),
      version = release$version,
      nonce = kng_server_nonce()
    ),
    expected_status = 201L
  )
  token <- session$access_token %||% ""
  token_type <- tolower(session$token_type %||% "")
  session_version <- kng_normalize_version(session$version %||% "")
  if (!is.character(token) ||
      length(token) != 1L ||
      !nzchar(token) ||
      !grepl("^[A-Za-z0-9._~-]{16,4096}$", token, perl = TRUE) ||
      !identical(token_type, "bearer") ||
      !identical(session_version, release$version)) {
    stop(
      "The knhanes authorization server returned an invalid install session.",
      call. = FALSE
    )
  }
  release$access_token <- token
  release
}

kng_github_headers <- function() {
  headers <- c(
    Accept = "application/vnd.github+json",
    `X-GitHub-Api-Version` = "2022-11-28"
  )
  token <- Sys.getenv("GITHUB_TOKEN", unset = "")
  if (!nzchar(token)) {
    token <- Sys.getenv("GH_TOKEN", unset = "")
  }
  if (nzchar(token)) {
    headers <- c(headers, Authorization = paste("Bearer", token))
  }
  headers
}

kng_fetch_json <- function(url) {
  handle <- curl::new_handle(
    useragent = paste0("knhanesget/", utils::packageVersion("knhanesget"))
  )
  curl::handle_setheaders(
    handle,
    .list = as.list(kng_github_headers())
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

kng_download_headers <- function(access_token = NULL) {
  if (is.null(access_token)) {
    return(character())
  }
  kng_scalar_character(access_token, "install session access token")
  if (!grepl(
    "^[A-Za-z0-9._~-]{16,4096}$",
    access_token,
    perl = TRUE
  )) {
    stop("The install session access token is invalid.", call. = FALSE)
  }
  c(Authorization = paste("Bearer", access_token))
}

kng_download <- function(url,
                         path,
                         quiet = FALSE,
                         access_token = NULL) {
  headers <- kng_download_headers(access_token)
  handle <- curl::new_handle(
    useragent = paste0("knhanesget/", utils::packageVersion("knhanesget"))
  )
  if (length(headers) > 0L) {
    curl::handle_setheaders(
      handle,
      Authorization = unname(headers[["Authorization"]])
    )
  }
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

kng_download_release_assets <- function(release, work, quiet = FALSE) {
  archive <- file.path(work, release$archive_name)
  paths <- list(
    archive = archive,
    checksum = paste0(archive, ".sha256"),
    signature = paste0(archive, ".sig")
  )
  urls <- list(
    archive = release$archive_url,
    checksum = release$checksum_url,
    signature = release$signature_url
  )
  for (kind in names(paths)) {
    kng_download(
      urls[[kind]],
      paths[[kind]],
      quiet = quiet,
      access_token = release$access_token
    )
  }
  paths
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
