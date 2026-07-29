test_that("archive verification accepts matching signed assets", {
  key <- sodium::sig_keygen()
  public <- sodium::sig_pubkey(key)
  archive <- tempfile(fileext = ".tar.gz")
  checksum <- paste0(archive, ".sha256")
  signature <- paste0(archive, ".sig")
  writeBin(charToRaw("test archive bytes"), archive)
  bytes <- readBin(archive, "raw", n = file.info(archive)$size)
  writeLines(sodium::bin2hex(sodium::sha256(bytes)), checksum)
  writeLines(sodium::bin2hex(sodium::sig_sign(bytes, key)), signature)

  local_mocked_bindings(
    .kng_release_public_key_hex = sodium::bin2hex(public),
    .package = "knhanesget"
  )
  expect_invisible(knhanesget:::kng_verify_archive(
    archive,
    checksum,
    signature
  ))

  writeBin(charToRaw("tampered"), archive)
  expect_error(
    knhanesget:::kng_verify_archive(archive, checksum, signature),
    "SHA-256"
  )
})

test_that("release metadata requires all signed assets", {
  fake_release <- list(
    tag_name = "v0.1.0.4",
    html_url = "https://example.test/release",
    assets = list(
      list(
        name = "knhanes_0.1.0.4.tar.gz",
        browser_download_url = "https://example.test/archive"
      )
    )
  )
  local_mocked_bindings(
    kng_fetch_json = function(url) fake_release,
    .package = "knhanesget"
  )
  expect_error(
    knhanesget:::kng_release_metadata("latest"),
    "does not contain"
  )
})

test_that("release metadata resolves asset URLs", {
  version <- "0.1.0.4"
  base <- paste0("knhanes_", version, ".tar.gz")
  fake_release <- list(
    tag_name = paste0("v", version),
    html_url = "https://example.test/release",
    assets = lapply(c(base, paste0(base, ".sha256"), paste0(base, ".sig")),
      function(name) list(
        name = name,
        browser_download_url = paste0("https://example.test/", name)
      )
    )
  )
  local_mocked_bindings(
    kng_fetch_json = function(url) fake_release,
    .package = "knhanesget"
  )
  result <- knhanesget:::kng_release_metadata("latest")
  expect_identical(result$version, version)
  expect_identical(result$tag, "v0.1.0.4")
  expect_true(endsWith(result$signature_url, ".sig"))
})

test_that("GitHub metadata headers use an optional environment token", {
  withr::local_envvar(c(GITHUB_TOKEN = NA, GH_TOKEN = NA))
  anonymous <- knhanesget:::kng_github_headers()
  expect_false("Authorization" %in% names(anonymous))
  expect_identical(
    unname(anonymous[["X-GitHub-Api-Version"]]),
    "2022-11-28"
  )

  withr::local_envvar(GITHUB_TOKEN = "test-actions-token")
  authenticated <- knhanesget:::kng_github_headers()
  expect_identical(
    unname(authenticated[["Authorization"]]),
    "Bearer test-actions-token"
  )
})

test_that("server is default and GitHub remains an explicit fallback", {
  withr::local_options(knhanesget.release_source = NULL)
  withr::local_envvar(KNHANESGET_RELEASE_SOURCE = NA_character_)
  expect_identical(knhanesget:::kng_release_source(), "server")

  withr::local_options(knhanesget.server_base_url = NULL)
  withr::local_envvar(KNHANESGET_SERVER_BASE_URL = NA_character_)
  expect_identical(
    knhanesget:::kng_server_base_url(),
    "https://api.knhanesr.com"
  )

  withr::local_envvar(KNHANESGET_RELEASE_SOURCE = "server")
  withr::local_options(knhanesget.release_source = "github")
  expect_identical(knhanesget:::kng_release_source(), "github")

  withr::local_options(knhanesget.release_source = "server")
  expect_identical(knhanesget:::kng_release_source(), "server")

  withr::local_options(knhanesget.release_source = "other")
  expect_error(
    knhanesget:::kng_release_source(),
    "must be 'github' or 'server'",
    fixed = TRUE
  )
})

test_that("server source requires a credential-free HTTPS base URL", {
  invalid <- c(
    "http://api.example.test",
    "https://user:secret@api.example.test",
    "https://api.example.test?token=secret",
    "https://api.example.test#fragment"
  )
  for (value in invalid) {
    withr::local_options(knhanesget.server_base_url = value)
    expect_error(
      knhanesget:::kng_server_base_url(),
      "must be an HTTPS URL",
      fixed = TRUE
    )
  }

  withr::local_options(
    knhanesget.server_base_url = "https://api.example.test/base/"
  )
  expect_identical(
    knhanesget:::kng_server_base_url(),
    "https://api.example.test/base"
  )
})

test_that("server metadata uses public latest endpoint and protected paths", {
  withr::local_options(
    knhanesget.server_base_url = "https://api.example.test"
  )
  seen <- NULL
  local_mocked_bindings(
    kng_server_request_json = function(path,
                                       method = "GET",
                                       body = NULL,
                                       expected_status = 200L) {
      seen <<- list(
        path = path,
        method = method,
        body = body,
        expected_status = expected_status
      )
      list(
        version = "0.1.0.12",
        artifacts = list("archive", "checksum", "signature")
      )
    },
    .package = "knhanesget"
  )

  release <- knhanesget:::kng_server_release_metadata("latest")
  expect_identical(seen$path, "/v1/releases/latest")
  expect_identical(seen$method, "GET")
  expect_identical(release$version, "0.1.0.12")
  expect_identical(release$source, "server")
  expect_match(
    release$archive_url,
    "/v1/releases/0[.]1[.]0[.]12/artifacts/archive$"
  )
  expect_match(release$checksum_url, "/artifacts/checksum$")
  expect_match(release$signature_url, "/artifacts/signature$")
  expect_false(any(grepl("license|token|request", unlist(release), ignore.case = TRUE)))
})

test_that("server install session uses body credentials and a short bearer token", {
  withr::local_options(
    knhanesget.server_base_url = "https://api.example.test"
  )
  seen <- NULL
  local_mocked_bindings(
    kng_local_license_code = function(license_code = NULL) {
      if (is.null(license_code)) "KNHLIC3.saved-license" else license_code
    },
    getToken = function(version = NULL, quiet = FALSE) {
      "KNHREQ2.saved-request"
    },
    kng_server_nonce = function() "abcdefghijklmnop",
    kng_server_request_json = function(path,
                                       method = "GET",
                                       body = NULL,
                                       expected_status = 200L) {
      seen <<- list(
        path = path,
        method = method,
        body = body,
        expected_status = expected_status
      )
      list(
        access_token = "short-lived-session-token",
        token_type = "bearer",
        expires_in = 300L,
        version = "0.1.0.12"
      )
    },
    .package = "knhanesget"
  )
  release <- knhanesget:::kng_server_release_metadata("0.1.0.12")
  authorized <- knhanesget:::kng_authorize_server_release(release)

  expect_identical(seen$path, "/v1/install-sessions")
  expect_identical(seen$method, "POST")
  expect_identical(seen$expected_status, 201L)
  expect_identical(seen$body$request_code, "KNHREQ2.saved-request")
  expect_identical(seen$body$license_code, "KNHLIC3.saved-license")
  expect_identical(seen$body$version, "0.1.0.12")
  expect_match(seen$body$nonce, "^[A-Za-z0-9_-]{16,64}$")
  expect_identical(
    authorized$access_token,
    "short-lived-session-token"
  )
  expect_false(grepl("KNHLIC3|KNHREQ2|session-token", authorized$archive_url))
})

test_that("saved local license is reused without changing public installer formals", {
  local_knhanesget_config()
  knhanesget:::kng_write_private_file(
    "KNHLIC3.saved-license",
    knhanesget:::kng_license_path()
  )
  expect_identical(
    knhanesget:::kng_local_license_code(),
    "KNHLIC3.saved-license"
  )
  expect_identical(
    names(formals(knhanesget::install_knhanes)),
    c("license_code", "version", "force", "quiet", "lib")
  )
})

test_that("protected downloads put the session token only in Authorization", {
  headers <- knhanesget:::kng_download_headers("short-lived-token")
  expect_identical(
    unname(headers[["Authorization"]]),
    "Bearer short-lived-token"
  )
  expect_identical(
    knhanesget:::kng_download_headers(),
    character()
  )
  expect_error(
    knhanesget:::kng_download_headers("valid-token-value\nInjected: yes"),
    "access token is invalid",
    fixed = TRUE
  )
})

test_that("all protected release assets reuse the in-memory bearer token", {
  work <- tempfile("protected-assets-")
  dir.create(work)
  on.exit(unlink(work, recursive = TRUE), add = TRUE)
  calls <- list()
  local_mocked_bindings(
    kng_download = function(url,
                            path,
                            quiet = FALSE,
                            access_token = NULL) {
      calls[[length(calls) + 1L]] <<- list(
        url = url,
        path = path,
        quiet = quiet,
        access_token = access_token
      )
      writeLines("asset", path)
      invisible(path)
    },
    .package = "knhanesget"
  )
  release <- list(
    archive_name = "knhanes_0.1.0.12.tar.gz",
    archive_url = "https://api.example.test/artifacts/archive",
    checksum_url = "https://api.example.test/artifacts/checksum",
    signature_url = "https://api.example.test/artifacts/signature",
    access_token = "short-lived-token"
  )
  paths <- knhanesget:::kng_download_release_assets(
    release,
    work,
    quiet = TRUE
  )

  expect_length(calls, 3L)
  expect_true(all(vapply(
    calls,
    function(x) identical(x$access_token, "short-lived-token"),
    logical(1)
  )))
  expect_true(all(file.exists(unlist(paths, use.names = FALSE))))
  expect_false(any(grepl(
    "short-lived-token",
    vapply(calls, `[[`, character(1), "url"),
    fixed = TRUE
  )))
})
