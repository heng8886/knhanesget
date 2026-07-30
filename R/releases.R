kng_server_base_url <- function() {
  base <- .kng_default_server_base_url
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
    safe_message <- kng_server_error_message(response$content)
    if (!is.null(safe_message)) {
      stop(safe_message, call. = FALSE)
    }
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

kng_server_error_message <- function(content) {
  if (!is.raw(content)) {
    return(NULL)
  }
  payload <- tryCatch(
    jsonlite::fromJSON(rawToChar(content), simplifyVector = FALSE),
    error = function(e) NULL
  )
  if (!is.list(payload)) {
    return(NULL)
  }
  candidates <- list(payload$error, payload$detail, payload$code)
  nested <- unlist(lapply(
    candidates,
    function(value) {
      if (!is.list(value)) {
        return(list(value))
      }
      list(value$code, value$error, value$detail, value$status)
    }
  ), recursive = FALSE)
  candidates <- c(candidates, nested)
  candidates <- vapply(
    candidates,
    function(value) {
      if (is.character(value) && length(value) == 1L && !is.na(value)) {
        tolower(trimws(value))
      } else {
        ""
      }
    },
    character(1)
  )
  candidates <- gsub("[^a-z0-9]+", "_", candidates)
  candidates <- gsub("^_+|_+$", "", candidates)
  if (any(candidates %in% c(
    "pending",
    "not_approved",
    "approval_pending",
    "license_request_pending",
    "request_not_approved"
  ))) {
    return(paste0(
      "The knhanes license request is pending approval. ",
      "After the administrator approves it, rerun install_knhanes()."
    ))
  }
  if (any(candidates %in% c(
    "denied",
    "request_denied",
    "license_denied"
  ))) {
    return(
      "The knhanes license request was denied. Contact the administrator."
    )
  }
  if (any(candidates %in% c(
    "revoked",
    "license_revoked",
    "device_revoked",
    "revoked_entitlement"
  ))) {
    return(
      "The knhanes license has been revoked. Contact the administrator."
    )
  }
  if (any(candidates %in% c(
    "expired",
    "license_expired",
    "request_expired",
    "challenge_expired",
    "expired_entitlement"
  ))) {
    return(paste0(
      "The knhanes authorization has expired. Run getToken() and request ",
      "approval again."
    ))
  }
  if (any(candidates %in% c(
    "key_conflict",
    "device_key_conflict",
    "public_key_conflict",
    "invalid_device_signature",
    "device_signature_invalid"
  ))) {
    return(paste0(
      "The registered knhanes device keys do not match this installation. ",
      "Do not replace the local keys; contact the administrator."
    ))
  }
  if (any(candidates %in% c(
    "device_proof_required",
    "proof_required",
    "device_signature_required"
  ))) {
    return(paste0(
      "The knhanes authorization server requires registered device proof. ",
      "Run getToken() on this device and wait for approval before retrying."
    ))
  }
  if (any(candidates %in% "legacy_install_flow_disabled")) {
    return(paste0(
      "The legacy knhanes install flow is disabled. Run getToken() on this ",
      "device, wait for approval, and then rerun install_knhanes()."
    ))
  }
  if (any(candidates %in% c(
    "invalid_challenge",
    "challenge_invalid",
    "invalid_or_expired_challenge",
    "replayed_challenge",
    "challenge_replayed",
    "challenge_already_used"
  ))) {
    return(
      "The knhanes device challenge is invalid or has already been used."
    )
  }
  NULL
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
    access_token = NULL,
    activation_license_code = NULL
  )
}

kng_local_license_code <- function(license_code = NULL, required = TRUE) {
  kng_scalar_logical(required, "required")
  if (!is.null(license_code)) {
    kng_scalar_character(license_code, "license_code")
    return(trimws(license_code))
  }
  path <- kng_license_path()
  if (!file.exists(path)) {
    if (!required) {
      return(NULL)
    }
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

kng_use_device_authorization <- function(license_code = NULL,
                                         local_license = NULL) {
  if (!is.null(license_code)) {
    return(FALSE)
  }
  request_code <- kng_saved_license_request(required = FALSE)
  if (is.null(request_code)) {
    return(is.null(local_license))
  }
  kng_saved_license_request_version(required = TRUE)
  kng_installation_id(required = TRUE)
  kng_device_signing_key(required = TRUE)
  kng_device_encryption_key(required = TRUE)
  TRUE
}

kng_authorize_server_release <- function(release, license_code = NULL) {
  code <- kng_local_license_code(license_code, required = FALSE)
  use_device <- kng_use_device_authorization(license_code, code)
  session <- if (use_device) {
    kng_device_install_session(release)
  } else {
    kng_licensed_install_session(release, code)
  }
  release <- kng_apply_install_session(release, session)
  if (use_device) {
    release$activation_license_code <- kng_decrypt_activation_envelope(
      session$activation_envelope %||% ""
    )
  }
  release
}

kng_licensed_install_session <- function(release, license_code) {
  if (!grepl("^KNHLIC3\\.", license_code, perl = TRUE)) {
    stop(
      "The authorization server compatibility path accepts only KNHLIC3 ",
      "license codes. KNHLIC1 or KNHLIC2 codes may be used only for local ",
      "activation when supported by the installed knhanes version.",
      call. = FALSE
    )
  }
  request_code <- kng_legacy_request_code(release$version)
  kng_server_request_json(
    "/v1/install-sessions",
    method = "POST",
    body = list(
      request_code = unname(request_code),
      license_code = unname(license_code),
      version = release$version,
      nonce = kng_server_nonce()
    ),
    expected_status = 201L
  )
}

kng_legacy_request_code <- function(version) {
  version <- kng_normalize_version(version)
  body <- c(
    sodium::hex2bin(kng_installation_id()),
    charToRaw(paste0(version, "\n", kng_local_username()))
  )
  checksum <- kng_base64url_encode(sodium::sha256(body)[seq_len(6L)])
  paste(
    "KNHREQ2",
    kng_base64url_encode(body),
    checksum,
    sep = "."
  )
}

kng_device_install_session <- function(release) {
  request_code <- kng_saved_license_request()
  signing_key <- kng_device_signing_key(required = TRUE)
  signing_public_key <- sodium::sig_pubkey(signing_key)
  encryption_public_key <- sodium::pubkey(
    kng_device_encryption_key(required = TRUE)
  )
  signing_fingerprint <- kng_public_key_fingerprint(signing_public_key)
  encryption_fingerprint <- kng_public_key_fingerprint(encryption_public_key)
  challenge <- kng_device_install_challenge(
    release,
    request_code,
    signing_key,
    signing_fingerprint,
    encryption_fingerprint
  )
  nonce <- kng_server_nonce()
  message <- kng_device_signature_message(
    "knhanes-device-install-session-v1",
    kng_server_base_url(),
    kng_installation_id(required = TRUE),
    signing_fingerprint,
    encryption_fingerprint,
    request_code,
    challenge$version,
    challenge$challenge_id,
    challenge$challenge,
    nonce
  )
  kng_server_request_json(
    "/v1/device-install-sessions",
    method = "POST",
    body = list(
      request_code = request_code,
      version = challenge$version,
      challenge_id = challenge$challenge_id,
      challenge = challenge$challenge,
      nonce = nonce,
      signature = kng_base64url_encode(
        sodium::sig_sign(message, signing_key)
      )
    ),
    expected_status = 201L
  )
}

kng_device_install_challenge <- function(release,
                                         request_code,
                                         signing_key,
                                         signing_fingerprint,
                                         encryption_fingerprint) {
  nonce <- kng_server_nonce()
  installation_id <- kng_installation_id(required = TRUE)
  message <- kng_device_signature_message(
    "knhanes-device-challenge-request-v1",
    kng_server_base_url(),
    installation_id,
    signing_fingerprint,
    encryption_fingerprint,
    request_code,
    release$version,
    nonce
  )
  challenge <- kng_server_request_json(
    "/v1/device-challenges",
    method = "POST",
    body = list(
      request_code = request_code,
      version = release$version,
      installation_id = installation_id,
      nonce = nonce,
      signature = kng_base64url_encode(
        sodium::sig_sign(message, signing_key)
      )
    ),
    expected_status = c(200L, 201L)
  )
  challenge_id <- challenge$challenge_id %||% ""
  challenge_value <- challenge$challenge %||% ""
  challenge_version <- challenge$version %||% ""
  if (!is.character(challenge_id) ||
      length(challenge_id) != 1L ||
      !grepl("^[A-Za-z0-9._~-]{8,256}$", challenge_id, perl = TRUE) ||
      !is.character(challenge_value) ||
      length(challenge_value) != 1L ||
      !grepl("^[A-Za-z0-9_-]{16,1024}$", challenge_value, perl = TRUE) ||
      !is.character(challenge_version) ||
      length(challenge_version) != 1L ||
      !identical(challenge_version, release$version)) {
    stop(
      "The knhanes authorization server returned an invalid device challenge.",
      call. = FALSE
    )
  }
  list(
    challenge_id = challenge_id,
    challenge = challenge_value,
    version = challenge_version
  )
}

kng_public_key_fingerprint <- function(public_key) {
  if (!is.raw(public_key) || length(public_key) != 32L) {
    stop("The device public key is invalid.", call. = FALSE)
  }
  kng_base64url_encode(sodium::sha256(public_key))
}

kng_apply_install_session <- function(release, session) {
  token <- session$access_token %||% ""
  token_type <- tolower(session$token_type %||% "")
  session_version <- session$version %||% ""
  if (!is.character(token) ||
      length(token) != 1L ||
      !nzchar(token) ||
      !grepl("^[A-Za-z0-9._~-]{16,4096}$", token, perl = TRUE) ||
      !identical(token_type, "bearer") ||
      !is.character(session_version) ||
      length(session_version) != 1L ||
      !identical(session_version, release$version)) {
    stop(
      "The knhanes authorization server returned an invalid install session.",
      call. = FALSE
    )
  }
  release$access_token <- token
  release
}

kng_decrypt_activation_envelope <- function(envelope) {
  if (!is.character(envelope) ||
      length(envelope) != 1L ||
      !grepl("^[A-Za-z0-9_-]{32,4096}$", envelope, perl = TRUE)) {
    stop(
      "The knhanes authorization server returned an invalid activation envelope.",
      call. = FALSE
    )
  }
  ciphertext <- tryCatch(
    kng_base64url_decode(envelope),
    error = function(e) NULL
  )
  plaintext <- tryCatch(
    sodium::simple_decrypt(
      ciphertext,
      kng_device_encryption_key(required = TRUE)
    ),
    error = function(e) NULL
  )
  code <- tryCatch(
    rawToChar(plaintext),
    error = function(e) ""
  )
  if (!is.raw(plaintext) ||
      !grepl(
        "^KNHLIC3\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$",
        code,
        perl = TRUE
      )) {
    stop(
      "The knhanes activation envelope could not be authenticated for this device.",
      call. = FALSE
    )
  }
  code
}

`%||%` <- function(x, y) {
  if (is.null(x)) y else x
}

kng_download_headers <- function(access_token = NULL) {
  if (is.null(access_token)) {
    stop(
      "A short-lived install session access token is required.",
      call. = FALSE
    )
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
