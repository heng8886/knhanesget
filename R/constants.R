.kng_package <- "knhanes"
.kng_contact <- "henry88866@163.com"
.kng_dist_owner <- "heng8886"
.kng_dist_repo <- "knhanes-dist"
.kng_fallback_version <- "0.1.0.4"
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

kng_installation_path <- function() {
  file.path(kng_config_dir(), "installation-id-v1.txt")
}

kng_license_path <- function() {
  file.path(kng_config_dir(), "license-v1.txt")
}

kng_ensure_config_dir <- function() {
  path <- kng_config_dir()
  if (!dir.exists(path)) {
    dir.create(path, recursive = TRUE, showWarnings = FALSE, mode = "0700")
  }
  if (!dir.exists(path)) {
    stop("Cannot create the knhanes configuration directory: ", path,
         call. = FALSE)
  }
  path
}

kng_write_private_file <- function(value, path) {
  kng_ensure_config_dir()
  tmp <- tempfile(".knhanesget-", tmpdir = dirname(path))
  on.exit(unlink(tmp), add = TRUE)
  writeLines(value, tmp, useBytes = TRUE)
  Sys.chmod(tmp, mode = "0600")
  if (!file.rename(tmp, path)) {
    stop("Cannot save configuration file: ", path, call. = FALSE)
  }
  Sys.chmod(path, mode = "0600")
  invisible(path)
}

kng_installation_id <- function() {
  path <- kng_installation_path()
  if (file.exists(path)) {
    value <- trimws(readLines(path, n = 1L, warn = FALSE))
    if (grepl("^[0-9a-f]{32}$", value)) {
      return(value)
    }
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
