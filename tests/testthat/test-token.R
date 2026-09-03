mock_license_registration <- function(
    request_code = "KNHREQ3.abcdefghijklmnopqrstuvwxyz012345") {
  calls <- list()
  local_mocked_bindings(
    kng_server_request_json = function(path,
                                       method = "GET",
                                       body = NULL,
                                       expected_status = 200L) {
      calls[[length(calls) + 1L]] <<- list(
        path = path,
        method = method,
        body = body,
        expected_status = expected_status
      )
      list(request_code = request_code)
    },
    .package = "knhanesget",
    .env = parent.frame()
  )
  function() calls
}

test_that("getToken registers stable device keys and saves a short request", {
  config <- local_knhanesget_config()
  withr::local_options(knhanesget.username_test = "henry")
  calls <- mock_license_registration()

  first <- getToken(version = "0.1.0.13", quiet = TRUE)
  second <- getToken(version = "0.1.0.13", quiet = TRUE)
  seen <- calls()

  expect_identical(first, "KNHREQ3.abcdefghijklmnopqrstuvwxyz012345")
  expect_identical(second, first)
  expect_length(seen, 2L)
  expect_true(all(vapply(
    seen,
    function(call) identical(call$path, "/v1/license-requests"),
    logical(1)
  )))
  expect_true(all(vapply(
    seen,
    function(call) identical(call$method, "POST"),
    logical(1)
  )))
  expect_identical(
    seen[[1L]]$body$signing_public_key,
    seen[[2L]]$body$signing_public_key
  )
  expect_identical(
    seen[[1L]]$body$encryption_public_key,
    seen[[2L]]$body$encryption_public_key
  )
  expect_false(identical(
    seen[[1L]]$body$nonce,
    seen[[2L]]$body$nonce
  ))
  expect_identical(
    readLines(knhanesget:::kng_license_request_path(), warn = FALSE),
    first
  )
  expect_identical(
    readLines(
      knhanesget:::kng_license_request_version_path(),
      warn = FALSE
    ),
    "0.1.0.13"
  )
  expect_true(file.exists(knhanesget:::kng_device_signing_key_path()))
  expect_true(file.exists(knhanesget:::kng_device_encryption_key_path()))
  expect_identical(
    normalizePath(
      dirname(knhanesget:::kng_device_signing_key_path()),
      winslash = "/",
      mustWork = TRUE
    ),
    normalizePath(config, winslash = "/", mustWork = TRUE)
  )

  if (.Platform$OS.type != "windows") {
    expect_identical(
      bitwAnd(
        as.integer(file.info(config)$mode[[1L]]),
        511L
      ),
      448L
    )
    expect_identical(
      bitwAnd(
        as.integer(
          file.info(knhanesget:::kng_device_signing_key_path())$mode[[1L]]
        ),
        511L
      ),
      384L
    )
  }
})

test_that("registration canonical is NUL-delimited and API-bound", {
  local_knhanesget_config()
  withr::local_options(knhanesget.username_test = "test-user")
  calls <- mock_license_registration()

  getToken(version = "0.1.0.13", quiet = TRUE)
  body <- calls()[[1L]]$body
  message <- knhanesget:::kng_device_signature_message(
    "knhanes-device-registration-v1",
    "https://api.knhanesr.com",
    body$installation_id,
    body$version,
    body$username,
    body$signing_public_key,
    body$encryption_public_key,
    body$nonce
  )
  expect_identical(
    sum(message == as.raw(0L)),
    7L
  )
  expect_true(sodium::sig_verify(
    message,
    knhanesget:::kng_base64url_decode(body$signature),
    knhanesget:::kng_base64url_decode(body$signing_public_key)
  ))
  expect_identical(body$username, "test-user")
  expect_false(grepl(
    Sys.info()[["nodename"]],
    paste(unlist(body, use.names = FALSE), collapse = " "),
    fixed = TRUE
  ))
})

test_that("registration canonical and Ed25519 signature match golden vector", {
  fields <- c(
    "knhanes-device-registration-v1",
    "https://api.knhanesr.com",
    "00112233445566778899aabbccddeeff",
    "0.1.0.13",
    "alice",
    "c2lnbmluZy1wdWJsaWMta2V5",
    "ZW5jcnlwdGlvbi1wdWJsaWMta2V5",
    "bm9uY2U"
  )
  message <- do.call(
    knhanesget:::kng_device_signature_message,
    as.list(fields)
  )
  expected_hex <- paste0(
    "6b6e68616e65732d6465766963652d726567697374726174696f6e2d763100",
    "68747470733a2f2f6170692e6b6e68616e6573722e636f6d00",
    "303031313232333334343535363637373838393961616262636364646565666600",
    "302e312e302e313300616c69636500",
    "63326c6e626d6c755a79317764574a7361574d746132563500",
    "5a57356a636e6c7764476c766269317764574a7361574d746132563500",
    "626d3975593255"
  )
  expect_identical(sodium::bin2hex(message), expected_hex)

  signing_key <- knhanesget:::kng_base64url_decode(paste0(
    "tspQwHz8nlCKIOUIhEnr2YfReuB8drYGh9WXRm44DSZiVENRJGev7jFxUcyNf6FL",
    "xwOelRfZlprLJz1NlvelGQ"
  ))
  signature <- knhanesget:::kng_base64url_encode(
    sodium::sig_sign(message, signing_key)
  )
  expect_identical(
    signature,
    paste0(
      "znCzpTuEBHvhV6GjRFWZX8gHeGZYmrNB9kufLez4XQmJ2UsEZiAXbv6HpRdAZdKD",
      "Mgc2GMt2UZq-hcvUz8wgAg"
    )
  )
})

test_that("getToken prints approval instructions but not private keys", {
  local_knhanesget_config()
  withr::local_options(knhanesget.username_test = "henry")
  mock_license_registration()

  output <- capture.output(getToken(version = "0.1.0.13"))
  expect_true(any(grepl("请将完整申请码和姓名发送给我。", output, fixed = TRUE)))
  expect_true(any(grepl("邮箱：henry88866@163.com", output, fixed = TRUE)))
  expect_true(any(grepl(
    "knhanesget::install_knhanes()",
    output,
    fixed = TRUE
  )))
  signing_secret <- readLines(
    knhanesget:::kng_device_signing_key_path(),
    warn = FALSE
  )
  encryption_secret <- readLines(
    knhanesget:::kng_device_encryption_key_path(),
    warn = FALSE
  )
  expect_false(any(grepl(signing_secret, output, fixed = TRUE)))
  expect_false(any(grepl(encryption_secret, output, fixed = TRUE)))
})

test_that("getToken validates arguments and server request codes", {
  local_knhanesget_config()
  mock_license_registration(request_code = "invalid")
  expect_error(
    getToken(version = "0.1.0.13", quiet = TRUE),
    "invalid request code"
  )
  expect_error(getToken(version = "latest", quiet = TRUE), "dot-separated")
  expect_error(getToken(version = "0.1.0.13", quiet = NA), "TRUE or FALSE")
})

test_that("KNHREQ3 request codes require exactly 32 URL-safe characters", {
  local_knhanesget_config()
  valid_code <- paste0("KNHREQ3.", strrep("a", 32L))
  returned_code <- valid_code
  local_mocked_bindings(
    kng_server_request_json = function(path,
                                       method = "GET",
                                       body = NULL,
                                       expected_status = 200L) {
      list(request_code = returned_code)
    },
    .package = "knhanesget"
  )

  expect_identical(
    getToken(version = "0.1.0.13", quiet = TRUE),
    valid_code
  )
  expect_identical(
    knhanesget:::kng_saved_license_request(),
    valid_code
  )

  invalid_codes <- c(
    paste0("KNHREQ3.", strrep("a", 31L)),
    paste0("KNHREQ3.", strrep("a", 33L)),
    paste0("KNHREQ3.", strrep("a", 31L), "+")
  )
  for (invalid_code in invalid_codes) {
    returned_code <- invalid_code
    expect_error(
      getToken(version = "0.1.0.13", quiet = TRUE),
      "invalid request code"
    )
    knhanesget:::kng_write_private_file(
      invalid_code,
      knhanesget:::kng_license_request_path()
    )
    expect_error(
      knhanesget:::kng_saved_license_request(),
      "saved knhanes license request is invalid"
    )
  }
})

test_that("corrupt or symlinked private keys are never silently replaced", {
  local_knhanesget_config()
  path <- knhanesget:::kng_device_signing_key_path()
  knhanesget:::kng_write_private_file("corrupt", path)
  expect_error(
    knhanesget:::kng_device_signing_key(),
    "device signing key is invalid"
  )
  expect_identical(readLines(path, warn = FALSE), "corrupt")

  if (.Platform$OS.type != "windows") {
    unlink(path)
    target <- tempfile("outside-device-key-")
    writeLines("outside", target)
    expect_true(file.symlink(target, path))
    expect_error(
      knhanesget:::kng_device_signing_key(),
      "symbolic link"
    )
    expect_identical(readLines(target, warn = FALSE), "outside")
  }
})

test_that("Windows private-state branch delegates to ACL lockdown", {
  path <- tempfile("private-state-")
  writeLines("secret", path)
  seen <- NULL
  local_mocked_bindings(
    kng_is_windows = function() TRUE,
    kng_windows_acl_lockdown = function(path, is_directory = FALSE) {
      seen <<- list(path = path, is_directory = is_directory)
      invisible(path)
    },
    .package = "knhanesget"
  )

  expect_invisible(
    knhanesget:::kng_apply_private_permissions(
      path,
      is_directory = FALSE
    )
  )
  expect_identical(seen, list(path = path, is_directory = FALSE))
})

test_that("Windows ACL failure is fatal", {
  path <- tempfile("private-state-")
  writeLines("secret", path)
  local_mocked_bindings(
    kng_windows_principal = function() "DOMAIN\\user",
    kng_run_process = function(command, args) {
      list(status = 5L, output = "Access is denied.")
    },
    .package = "knhanesget"
  )

  expect_error(
    knhanesget:::kng_windows_acl_lockdown(path),
    "Cannot secure private knhanes state"
  )
})

test_that("Windows ACL lockdown is reread and verified", {
  path <- tempfile("private-state-")
  writeLines("secret", path)
  calls <- list()
  local_mocked_bindings(
    kng_windows_principal = function() "DOMAIN\\user",
    kng_run_process = function(command, args) {
      calls[[length(calls) + 1L]] <<- list(command = command, args = args)
      if (length(calls) == 1L) {
        return(list(status = 0L, output = "Successfully processed 1 files"))
      }
      list(
        status = 0L,
        output = paste0(path, " DOMAIN\\user:(F)")
      )
    },
    .package = "knhanesget"
  )

  expect_invisible(knhanesget:::kng_windows_acl_lockdown(path))
  expect_length(calls, 2L)
  expect_identical(calls[[1L]]$command, "icacls")
  expect_true("/inheritance:r" %in% calls[[1L]]$args)
  expect_true("*S-1-5-11" %in% calls[[1L]]$args)
  expect_identical(calls[[2L]], list(command = "icacls", args = path))
})

test_that("Windows ACL verification tolerates localized non-UTF-8 output", {
  path <- tempfile("private-state-")
  writeLines("secret", path)
  localized_cp936 <- rawToChar(as.raw(c(0xb3, 0xc9, 0xb9, 0xa6)))
  calls <- 0L
  local_mocked_bindings(
    kng_windows_principal = function() "DOMAIN\\User",
    kng_run_process = function(command, args) {
      calls <<- calls + 1L
      if (calls == 1L) {
        return(list(status = 0L, output = localized_cp936))
      }
      list(
        status = 0L,
        output = paste0(
          path,
          " domain\\user:(F)\n",
          localized_cp936
        )
      )
    },
    .package = "knhanesget"
  )

  expect_false(validUTF8(localized_cp936))
  expect_invisible(knhanesget:::kng_windows_acl_lockdown(path))
})

test_that("Windows ACL byte matching still rejects broad principals", {
  path <- tempfile("private-state-")
  writeLines("secret", path)
  localized_cp936 <- rawToChar(as.raw(c(0xb3, 0xc9, 0xb9, 0xa6)))
  calls <- 0L
  local_mocked_bindings(
    kng_windows_principal = function() "DOMAIN\\user",
    kng_run_process = function(command, args) {
      calls <<- calls + 1L
      if (calls == 1L) {
        return(list(status = 0L, output = localized_cp936))
      }
      list(
        status = 0L,
        output = paste0(
          path,
          " DOMAIN\\user:(F)\nS-1-5-11:(R)\n",
          localized_cp936
        )
      )
    },
    .package = "knhanesget"
  )

  expect_error(
    knhanesget:::kng_windows_acl_lockdown(path),
    "Cannot verify private Windows ACLs"
  )
})

test_that("Windows principal trimming accepts non-UTF-8 account bytes", {
  account_cp936 <- rawToChar(as.raw(c(0xd3, 0xc3, 0xbb, 0xa7)))
  principal <- paste0("  DOMAIN\\", account_cp936, "\r\n")
  local_mocked_bindings(
    kng_run_process = function(command, args) {
      list(status = 0L, output = principal)
    },
    .package = "knhanesget"
  )

  actual <- knhanesget:::kng_windows_principal()
  expect_identical(charToRaw(actual), charToRaw(paste0("DOMAIN\\", account_cp936)))
})

test_that("Windows ACL verification rejects broad principals", {
  path <- tempfile("private-state-")
  writeLines("secret", path)
  call_count <- 0L
  local_mocked_bindings(
    kng_windows_principal = function() "DOMAIN\\user",
    kng_run_process = function(command, args) {
      call_count <<- call_count + 1L
      if (call_count == 1L) {
        return(list(status = 0L, output = "Successfully processed 1 files"))
      }
      list(
        status = 0L,
        output = c(
          paste0(path, " DOMAIN\\user:(F)"),
          "S-1-1-0:(R)"
        )
      )
    },
    .package = "knhanesget"
  )

  expect_error(
    knhanesget:::kng_windows_acl_lockdown(path),
    "Cannot verify private Windows ACLs"
  )
})

test_that("Windows ACL integration excludes broad security principals", {
  skip_if(.Platform$OS.type != "windows")
  root <- tempfile("knhanesget-acl-integration-")
  dir.create(root)
  on.exit(unlink(root, recursive = TRUE, force = TRUE), add = TRUE)
  path <- file.path(root, "device-secret")

  knhanesget:::kng_write_private_file("secret", path)
  expect_true(file.exists(path))

  escaped <- gsub(
    "'",
    "''",
    normalizePath(path, winslash = "\\", mustWork = TRUE),
    fixed = TRUE
  )
  script <- paste0(
    "$ErrorActionPreference='Stop';",
    "$acl=Get-Acl -LiteralPath '", escaped, "';",
    "@($acl.Access) | ForEach-Object {",
    "$_.IdentityReference.Translate(",
    "[System.Security.Principal.SecurityIdentifier]",
    ").Value",
    "}"
  )
  result <- knhanesget:::kng_run_process(
    "powershell.exe",
    c("-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
  )
  expect_identical(result$status, 0L)
  sids <- unique(trimws(result$output))
  sids <- sids[grepl("^S-[0-9-]+$", sids)]
  expect_gt(length(sids), 0L)
  expect_length(
    intersect(
      sids,
      c("S-1-1-0", "S-1-5-11", "S-1-5-32-545")
    ),
    0L
  )
})
