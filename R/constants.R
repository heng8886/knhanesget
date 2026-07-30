.kng_package <- "knhanes"
.kng_contact <- "henry88866@163.com"
.kng_default_server_base_url <- "https://api.knhanesr.com"
.kng_compatible_core_version <- "0.1.0.13"
.kng_release_public_key_hex <- paste0(
  "707493cd033160cc5245f52379032463",
  "715ccdd4adc115b513f6d8fb796ee02c"
)

kng_scalar_character <- function(x, name, allow_empty = FALSE) {
  ok <- is.character(x) && length(x) == 1L && !is.na(x)
  if (ok && !allow_empty) {
    ok <- nzchar(trimws(x))
  }
  if (!ok) {
    stop(name, " must be one non-missing character string.", call. = FALSE)
  }
  invisible(TRUE)
}

kng_scalar_logical <- function(x, name) {
  if (!is.logical(x) || length(x) != 1L || is.na(x)) {
    stop(name, " must be TRUE or FALSE.", call. = FALSE)
  }
  invisible(TRUE)
}

kng_normalize_version <- function(version) {
  kng_scalar_character(version, "version")
  version <- sub("^v", "", trimws(version))
  if (!grepl("^[0-9]+(?:\\.[0-9]+)+$", version, perl = TRUE)) {
    stop("version must contain dot-separated integers, optionally prefixed by 'v'.",
         call. = FALSE)
  }
  version
}

kng_config_dir <- function() {
  test_dir <- getOption("knhanesget.config_dir_test", NULL)
  if (identical(Sys.getenv("TESTTHAT"), "true") &&
      is.character(test_dir) && length(test_dir) == 1L && nzchar(test_dir)) {
    return(path.expand(test_dir))
  }
  tools::R_user_dir("knhanes", which = "config")
}

kng_device_config_dir <- function() {
  test_dir <- getOption("knhanesget.device_config_dir_test", NULL)
  if (identical(Sys.getenv("TESTTHAT"), "true") &&
      is.character(test_dir) && length(test_dir) == 1L && nzchar(test_dir)) {
    return(path.expand(test_dir))
  }
  tools::R_user_dir("knhanesget", which = "config")
}

kng_installation_path <- function() {
  file.path(kng_config_dir(), "installation-id-v1.txt")
}

kng_license_path <- function() {
  file.path(kng_config_dir(), "license-v1.txt")
}

kng_device_signing_key_path <- function() {
  file.path(kng_device_config_dir(), "device-signing-key-v1.txt")
}

kng_device_encryption_key_path <- function() {
  file.path(kng_device_config_dir(), "device-encryption-key-v1.txt")
}

kng_license_request_path <- function() {
  file.path(kng_device_config_dir(), "license-request-v3.txt")
}

kng_license_request_version_path <- function() {
  file.path(kng_device_config_dir(), "license-request-v3-version.txt")
}

kng_ensure_config_dir <- function() {
  kng_ensure_private_dir(kng_config_dir())
}

kng_ensure_private_dir <- function(path) {
  kng_scalar_character(path, "configuration directory")
  if (kng_path_is_symlink(path)) {
    stop(
      "Refusing to use a symbolic link as a knhanes configuration directory: ",
      path,
      call. = FALSE
    )
  }
  if (!dir.exists(path)) {
    dir.create(path, recursive = TRUE, showWarnings = FALSE, mode = "0700")
  }
  if (!dir.exists(path)) {
    stop("Cannot create the knhanes configuration directory: ", path,
         call. = FALSE)
  }
  kng_apply_private_permissions(path, is_directory = TRUE)
  path
}

kng_write_private_file <- function(value, path) {
  kng_scalar_character(path, "configuration file path")
  if (kng_path_is_symlink(path)) {
    stop(
      "Refusing to replace a symbolic link used for private knhanes state: ",
      path,
      call. = FALSE
    )
  }
  if (file.exists(path)) {
    current <- readLines(path, warn = FALSE)
    if (identical(current, as.character(value))) {
      kng_apply_private_permissions(path, is_directory = FALSE)
      return(invisible(path))
    }
  }
  kng_ensure_private_dir(dirname(path))
  tmp <- tempfile(".knhanesget-", tmpdir = dirname(path))
  on.exit(unlink(tmp), add = TRUE)
  writeLines(value, tmp, useBytes = TRUE)
  kng_apply_private_permissions(tmp, is_directory = FALSE)
  replaced <- if (kng_is_windows() && file.exists(path)) {
    backup <- tempfile(".knhanesget-backup-", tmpdir = dirname(path))
    if (!file.rename(path, backup)) {
      FALSE
    } else if (file.rename(tmp, path)) {
      unlink(backup)
      TRUE
    } else {
      file.rename(backup, path)
      FALSE
    }
  } else {
    file.rename(tmp, path)
  }
  if (!replaced) {
    stop("Cannot save configuration file: ", path, call. = FALSE)
  }
  kng_apply_private_permissions(path, is_directory = FALSE)
  invisible(path)
}

kng_path_is_symlink <- function(path) {
  link <- tryCatch(Sys.readlink(path), error = function(e) "")
  length(link) == 1L && !is.na(link) && nzchar(link)
}

kng_is_windows <- function() {
  identical(.Platform$OS.type, "windows")
}

kng_apply_private_permissions <- function(path, is_directory = FALSE) {
  kng_scalar_character(path, "private state path")
  kng_scalar_logical(is_directory, "is_directory")
  if (kng_path_is_symlink(path)) {
    stop(
      "Refusing to secure a symbolic link used for private knhanes state: ",
      path,
      call. = FALSE
    )
  }
  if (kng_is_windows()) {
    kng_windows_acl_lockdown(path, is_directory)
    return(invisible(path))
  }
  expected <- if (is_directory) "0700" else "0600"
  Sys.chmod(path, mode = expected)
  info <- file.info(path)
  actual <- if (nrow(info) == 1L && !is.na(info$mode[[1L]])) {
    bitwAnd(as.integer(info$mode[[1L]]), 511L)
  } else {
    NA_integer_
  }
  required <- if (is_directory) 448L else 384L
  if (is.na(actual) || actual != required) {
    stop(
      "Cannot enforce private permissions ", expected, " on: ", path,
      call. = FALSE
    )
  }
  invisible(path)
}

kng_windows_principal <- function() {
  result <- kng_run_process("whoami", character())
  principal <- if (length(result$output)) {
    trimws(result$output[[1L]])
  } else {
    ""
  }
  if (result$status != 0L ||
      !nzchar(principal) ||
      grepl("[\r\n]", principal) ||
      nchar(principal, type = "bytes") > 256L) {
    stop(
      "Cannot determine the current Windows account for private key ACLs.",
      call. = FALSE
    )
  }
  principal
}

kng_windows_acl_lockdown <- function(path, is_directory = FALSE) {
  principal <- kng_windows_principal()
  permission <- if (is_directory) "(OI)(CI)F" else "F"
  result <- kng_run_process(
    "icacls",
    c(
      path,
      "/inheritance:r",
      "/grant:r",
      paste0(principal, ":", permission),
      "/remove:g",
      "*S-1-1-0",
      "*S-1-5-32-545",
      "*S-1-5-11"
    )
  )
  if (result$status != 0L) {
    stop(
      "Cannot secure private knhanes state with Windows ACLs: ",
      path,
      call. = FALSE
    )
  }
  verification <- kng_run_process("icacls", path)
  acl <- paste(verification$output, collapse = "\n")
  if (verification$status != 0L ||
      !grepl(tolower(principal), tolower(acl), fixed = TRUE) ||
      grepl("S-1-1-0|S-1-5-32-545|S-1-5-11", acl, perl = TRUE)) {
    stop(
      "Cannot verify private Windows ACLs for knhanes state: ",
      path,
      call. = FALSE
    )
  }
  invisible(path)
}

kng_run_process <- function(command, args) {
  kng_scalar_character(command, "process command")
  if (!is.character(args) || anyNA(args)) {
    stop("process arguments must be character strings.", call. = FALSE)
  }
  output <- tryCatch(
    suppressWarnings(system2(
      command,
      args = vapply(args, shQuote, character(1)),
      stdout = TRUE,
      stderr = TRUE
    )),
    error = function(e) structure(character(), status = 127L)
  )
  status <- attr(output, "status") %||% 0L
  list(status = as.integer(status), output = output)
}

kng_read_private_key <- function(path, expected_bytes, label) {
  if (kng_path_is_symlink(path)) {
    stop(
      "Refusing to read a symbolic link used as the knhanes ",
      label,
      ".",
      call. = FALSE
    )
  }
  if (!file.exists(path)) {
    return(NULL)
  }
  kng_apply_private_permissions(path, is_directory = FALSE)
  encoded <- trimws(readLines(path, n = 1L, warn = FALSE))
  value <- tryCatch(
    kng_base64url_decode(encoded),
    error = function(e) NULL
  )
  if (is.null(value) || length(value) != expected_bytes) {
    stop(
      "The saved knhanes ", label,
      " is invalid. Reset the installation ID before requesting a new license.",
      call. = FALSE
    )
  }
  value
}

kng_device_signing_key <- function(required = FALSE) {
  kng_scalar_logical(required, "required")
  path <- kng_device_signing_key_path()
  value <- kng_read_private_key(path, 64L, "device signing key")
  if (!is.null(value)) {
    return(value)
  }
  if (required) {
    stop(
      "The registered knhanes device signing key is missing. Run ",
      "deactivate_device(confirm = TRUE, reset_installation_id = TRUE), ",
      "then run getToken() and request approval again.",
      call. = FALSE
    )
  }
  value <- sodium::sig_keygen()
  kng_write_private_file(kng_base64url_encode(value), path)
  value
}

kng_device_encryption_key <- function(required = FALSE) {
  kng_scalar_logical(required, "required")
  path <- kng_device_encryption_key_path()
  value <- kng_read_private_key(path, 32L, "device encryption key")
  if (!is.null(value)) {
    return(value)
  }
  if (required) {
    stop(
      "The registered knhanes device encryption key is missing. Run ",
      "deactivate_device(confirm = TRUE, reset_installation_id = TRUE), ",
      "then run getToken() and request approval again.",
      call. = FALSE
    )
  }
  value <- sodium::keygen()
  kng_write_private_file(kng_base64url_encode(value), path)
  value
}

kng_saved_license_request <- function(required = TRUE) {
  kng_scalar_logical(required, "required")
  path <- kng_license_request_path()
  if (!file.exists(path)) {
    if (!required) {
      return(NULL)
    }
    stop(
      "A registered knhanes license request was not found. Run getToken() ",
      "and wait for approval before installing.",
      call. = FALSE
    )
  }
  value <- trimws(readLines(path, n = 1L, warn = FALSE))
  if (!grepl("^KNHREQ3\\.[A-Za-z0-9_-]{32}$", value, perl = TRUE)) {
    stop(
      "The saved knhanes license request is invalid. Run getToken() again.",
      call. = FALSE
    )
  }
  value
}

kng_saved_license_request_version <- function(required = TRUE) {
  kng_scalar_logical(required, "required")
  path <- kng_license_request_version_path()
  if (!file.exists(path)) {
    if (!required) {
      return(NULL)
    }
    stop(
      "The saved knhanes license request version is missing. Run getToken() ",
      "again before installing.",
      call. = FALSE
    )
  }
  value <- trimws(readLines(path, n = 1L, warn = FALSE))
  tryCatch(
    kng_normalize_version(value),
    error = function(e) {
      stop(
        "The saved knhanes license request version is invalid. Run ",
        "getToken() again before installing.",
        call. = FALSE
      )
    }
  )
}

kng_installation_id <- function(required = FALSE) {
  kng_scalar_logical(required, "required")
  path <- kng_installation_path()
  if (file.exists(path)) {
    value <- trimws(readLines(path, n = 1L, warn = FALSE))
    if (grepl("^[0-9a-f]{32}$", value)) {
      return(value)
    }
    stop(
      "The saved knhanes installation ID is invalid. Reset the installation ",
      "ID before requesting a new license.",
      call. = FALSE
    )
  }
  if (required) {
    stop(
      "The installation ID for the registered knhanes device is missing. ",
      "Run deactivate_device(confirm = TRUE, reset_installation_id = TRUE), ",
      "then run getToken() and request approval again.",
      call. = FALSE
    )
  }
  value <- sodium::bin2hex(sodium::random(16L))
  kng_write_private_file(value, path)
  value
}

kng_local_username <- function() {
  test_username <- getOption("knhanesget.username_test", NULL)
  if (identical(Sys.getenv("TESTTHAT"), "true") &&
      is.character(test_username) && length(test_username) == 1L &&
      !is.na(test_username)) {
    username <- test_username
  } else {
    username <- unname(Sys.info()[["user"]])
    if (length(username) != 1L || is.na(username) || !nzchar(username)) {
      username <- Sys.getenv("USERNAME", unset = "")
    }
    if (!nzchar(username)) {
      username <- Sys.getenv("USER", unset = "")
    }
  }
  username <- enc2utf8(trimws(username))
  username <- gsub("[[:cntrl:]]+", "_", username)
  if (!nzchar(username)) {
    username <- "unknown"
  }
  while (nchar(username, type = "bytes") > 100L) {
    username <- substr(username, 1L, nchar(username) - 1L)
  }
  username
}

kng_base64url_encode <- function(raw) {
  value <- jsonlite::base64_enc(raw)
  value <- gsub("[\r\n]", "", value)
  value <- chartr("+/", "-_", value)
  sub("=+$", "", value)
}

kng_base64url_decode <- function(value) {
  kng_scalar_character(value, "base64url value")
  if (!grepl("^[A-Za-z0-9_-]+$", value, perl = TRUE)) {
    stop("The base64url value is invalid.", call. = FALSE)
  }
  canonical <- value
  value <- chartr("-_", "+/", value)
  padding <- (4L - nchar(value) %% 4L) %% 4L
  if (padding > 0L) {
    value <- paste0(value, strrep("=", padding))
  }
  decoded <- tryCatch(
    jsonlite::base64_dec(value),
    error = function(e) NULL
  )
  if (is.null(decoded) ||
      !identical(kng_base64url_encode(decoded), canonical)) {
    stop("The base64url value is invalid.", call. = FALSE)
  }
  decoded
}

kng_installed_version <- function(lib = NULL) {
  value <- tryCatch(
    suppressWarnings(utils::packageDescription(
      "knhanes",
      lib.loc = lib,
      fields = "Version"
    )),
    error = function(e) NA_character_
  )
  if (length(value) != 1L || is.na(value) || !nzchar(value)) {
    return(NA_character_)
  }
  unname(value)
}
