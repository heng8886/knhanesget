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

test_that("official server is pinned outside the isolated test hook", {
  expect_identical(
    knhanesget:::kng_server_base_url(),
    "https://api.knhanesr.com"
  )

  withr::local_options(
    knhanesget.release_source = "legacy",
    knhanesget.server_base_url = "https://untrusted.example.test"
  )
  withr::local_envvar(c(
    KNHANESGET_RELEASE_SOURCE = "legacy",
    KNHANESGET_SERVER_BASE_URL = "https://untrusted.example.test"
  ))
  expect_identical(
    knhanesget:::kng_server_base_url(),
    "https://api.knhanesr.com"
  )
  expect_false(exists(
    paste0("kng_", "release_", "source"),
    envir = asNamespace("knhanesget"),
    inherits = FALSE
  ))
})

test_that("official server constant requires a credential-free HTTPS URL", {
  invalid <- c(
    "http://api.example.test",
    "https://user:secret@api.example.test",
    "https://api.example.test?token=secret",
    "https://api.example.test#fragment"
  )
  for (value in invalid) {
    local_mocked_bindings(
      .kng_default_server_base_url = value,
      .package = "knhanesget"
    )
    expect_error(
      knhanesget:::kng_server_base_url(),
      "must be an HTTPS URL",
      fixed = TRUE
    )
  }

  local_mocked_bindings(
    .kng_default_server_base_url = "https://api.example.test/base/",
    .package = "knhanesget"
  )
  expect_identical(
    knhanesget:::kng_server_base_url(),
    "https://api.example.test/base"
  )
})

test_that("server errors expose only approved safe messages", {
  pending <- charToRaw(jsonlite::toJSON(
    list(detail = "not_approved", internal_secret = "never-print-this"),
    auto_unbox = TRUE
  ))
  message <- knhanesget:::kng_server_error_message(pending)
  expect_match(message, "pending approval", fixed = TRUE)
  expect_false(grepl("never-print-this", message, fixed = TRUE))

  replayed <- charToRaw(jsonlite::toJSON(
    list(error = list(code = "replayed_challenge", trace = "secret-trace")),
    auto_unbox = TRUE
  ))
  message <- knhanesget:::kng_server_error_message(replayed)
  expect_match(message, "already been used", fixed = TRUE)
  expect_false(grepl("secret-trace", message, fixed = TRUE))

  proof_required <- charToRaw(jsonlite::toJSON(
    list(detail = "device_proof_required", trace = "secret-proof-trace"),
    auto_unbox = TRUE
  ))
  message <- knhanesget:::kng_server_error_message(proof_required)
  expect_match(message, "requires registered device proof", fixed = TRUE)
  expect_false(grepl("secret-proof-trace", message, fixed = TRUE))

  wrong_signature <- charToRaw(jsonlite::toJSON(
    list(detail = "invalid_device_signature", trace = "secret-signature-trace"),
    auto_unbox = TRUE
  ))
  message <- knhanesget:::kng_server_error_message(wrong_signature)
  expect_match(message, "device keys do not match", fixed = TRUE)
  expect_false(grepl("secret-signature-trace", message, fixed = TRUE))

  exact_codes <- c(
    revoked_entitlement = "has been revoked",
    expired_entitlement = "has expired",
    invalid_or_expired_challenge = "invalid or has already been used",
    legacy_install_flow_disabled = "legacy knhanes install flow is disabled"
  )
  for (code in names(exact_codes)) {
    content <- charToRaw(jsonlite::toJSON(
      list(detail = code, internal = paste0("secret-", code)),
      auto_unbox = TRUE
    ))
    message <- knhanesget:::kng_server_error_message(content)
    expect_match(message, exact_codes[[code]], fixed = TRUE)
    expect_false(grepl(paste0("secret-", code), message, fixed = TRUE))
  }

  unknown <- charToRaw(jsonlite::toJSON(
    list(detail = "database said password=secret"),
    auto_unbox = TRUE
  ))
  expect_null(knhanesget:::kng_server_error_message(unknown))
})

test_that("challenge and install canonical messages match golden vectors", {
  signing_key <- knhanesget:::kng_base64url_decode(paste0(
    "tspQwHz8nlCKIOUIhEnr2YfReuB8drYGh9WXRm44DSZiVENRJGev7jFxUcyNf6FL",
    "xwOelRfZlprLJz1NlvelGQ"
  ))
  vectors <- list(
    challenge = list(
      fields = c(
        "knhanes-device-challenge-request-v1",
        "https://api.knhanesr.com",
        "00112233445566778899aabbccddeeff",
        "signing-fingerprint",
        "encryption-fingerprint",
        "KNHREQ3.abcdefghijklmnopqrstuvwxyz012345",
        "0.1.0.13",
        "challenge-nonce"
      ),
      hex = paste0(
        "6b6e68616e65732d6465766963652d6368616c6c656e67652d726571756573742d763100",
        "68747470733a2f2f6170692e6b6e68616e6573722e636f6d003030313132323333343435",
        "353636373738383939616162626363646465656666007369676e696e672d66696e676572",
        "7072696e7400656e6372797074696f6e2d66696e6765727072696e74004b4e4852455133",
        "2e6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343500302e",
        "312e302e3133006368616c6c656e67652d6e6f6e6365"
      ),
      signature = paste0(
        "d1NILYf9fPtam96Cddx9L0e6qi5wVmQplXAjtCiBpwfjgCqHZUjfUgXQxmgjN3u6",
        "Tt4GbAGM0hy3-j5R44pfCw"
      )
    ),
    session = list(
      fields = c(
        "knhanes-device-install-session-v1",
        "https://api.knhanesr.com",
        "00112233445566778899aabbccddeeff",
        "signing-fingerprint",
        "encryption-fingerprint",
        "KNHREQ3.abcdefghijklmnopqrstuvwxyz012345",
        "0.1.0.13",
        "challenge-id-1234",
        "abcdefghijklmnopqrstuvwx",
        "session-nonce"
      ),
      hex = paste0(
        "6b6e68616e65732d6465766963652d696e7374616c6c2d73657373696f6e2d7631006874",
        "7470733a2f2f6170692e6b6e68616e6573722e636f6d0030303131323233333434353536",
        "36373738383939616162626363646465656666007369676e696e672d66696e6765727072",
        "696e7400656e6372797074696f6e2d66696e6765727072696e74004b4e48524551332e61",
        "62636465666768696a6b6c6d6e6f707172737475767778797a30313233343500302e312e",
        "302e3133006368616c6c656e67652d69642d31323334006162636465666768696a6b6c6d",
        "6e6f7071727374757677780073657373696f6e2d6e6f6e6365"
      ),
      signature = paste0(
        "VeY6VvGDxlkHzuG91XMOFUwx_VK7NstYtkwlBjB1q6-YmAHfW6VhJ3Bmgd0BjN9_",
        "P_tffWBayyUVy8fzrz2lDQ"
      )
    )
  )

  for (vector in vectors) {
    message <- do.call(
      knhanesget:::kng_device_signature_message,
      as.list(vector$fields)
    )
    expect_identical(sodium::bin2hex(message), vector$hex)
    expect_identical(
      knhanesget:::kng_base64url_encode(
        sodium::sig_sign(message, signing_key)
      ),
      vector$signature
    )
  }
})

test_that("server metadata uses public latest endpoint and protected paths", {
  local_mocked_bindings(
    .kng_default_server_base_url = "https://api.example.test",
    .package = "knhanesget"
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
  local_knhanesget_config()
  local_mocked_bindings(
    .kng_default_server_base_url = "https://api.example.test",
    .package = "knhanesget"
  )
  seen <- NULL
  local_mocked_bindings(
    kng_local_license_code = function(license_code = NULL, required = TRUE) {
      if (is.null(license_code)) "KNHLIC3.saved-license" else license_code
    },
    kng_legacy_request_code = function(version) {
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

test_that("registered device proof takes priority over a saved local license", {
  local_knhanesget_config()
  knhanesget:::kng_write_private_file(
    "KNHLIC3.saved-license",
    knhanesget:::kng_license_path()
  )
  knhanesget:::kng_write_private_file(
    "KNHREQ3.abcdefghijklmnopqrstuvwxyz012345",
    knhanesget:::kng_license_request_path()
  )
  knhanesget:::kng_write_private_file(
    "0.1.0.12",
    knhanesget:::kng_license_request_version_path()
  )
  knhanesget:::kng_installation_id()
  knhanesget:::kng_device_signing_key()
  knhanesget:::kng_device_encryption_key()
  device_calls <- 0L
  legacy_calls <- 0L
  local_mocked_bindings(
    kng_device_install_session = function(release) {
      device_calls <<- device_calls + 1L
      list(
        access_token = "registered-device-token",
        token_type = "bearer",
        version = release$version,
        activation_envelope = "encrypted-device-envelope"
      )
    },
    kng_licensed_install_session = function(release, license_code) {
      legacy_calls <<- legacy_calls + 1L
      stop("legacy install session must not run")
    },
    kng_decrypt_activation_envelope = function(envelope) {
      expect_identical(envelope, "encrypted-device-envelope")
      "KNHLIC3.device-license"
    },
    .package = "knhanesget"
  )

  release <- knhanesget:::kng_server_release_metadata("0.1.0.13")
  authorized <- knhanesget:::kng_authorize_server_release(release)

  expect_identical(device_calls, 1L)
  expect_identical(legacy_calls, 0L)
  expect_identical(authorized$access_token, "registered-device-token")
  expect_identical(
    authorized$activation_license_code,
    "KNHLIC3.device-license"
  )
})

test_that("explicit license code preserves the legacy install session path", {
  local_knhanesget_config()
  knhanesget:::kng_write_private_file(
    "KNHREQ3.abcdefghijklmnopqrstuvwxyz012345",
    knhanesget:::kng_license_request_path()
  )
  knhanesget:::kng_write_private_file(
    "0.1.0.12",
    knhanesget:::kng_license_request_version_path()
  )
  knhanesget:::kng_installation_id()
  knhanesget:::kng_device_signing_key()
  knhanesget:::kng_device_encryption_key()
  device_calls <- 0L
  legacy_code <- NULL
  local_mocked_bindings(
    kng_device_install_session = function(release) {
      device_calls <<- device_calls + 1L
      stop("device install session must not run")
    },
    kng_licensed_install_session = function(release, license_code) {
      legacy_code <<- license_code
      list(
        access_token = "explicit-legacy-token",
        token_type = "bearer",
        version = release$version
      )
    },
    .package = "knhanesget"
  )

  release <- knhanesget:::kng_server_release_metadata("0.1.0.13")
  authorized <- knhanesget:::kng_authorize_server_release(
    release,
    license_code = "KNHLIC3.explicit-license"
  )

  expect_identical(device_calls, 0L)
  expect_identical(legacy_code, "KNHLIC3.explicit-license")
  expect_identical(authorized$access_token, "explicit-legacy-token")
  expect_null(authorized$activation_license_code)
})

test_that("online legacy compatibility rejects KNHLIC1 and KNHLIC2", {
  release <- knhanesget:::kng_server_release_metadata("0.1.0.13")
  for (prefix in c("KNHLIC1", "KNHLIC2")) {
    expect_error(
      knhanesget:::kng_licensed_install_session(
        release,
        paste0(prefix, ".legacy-license")
      ),
      "accepts only KNHLIC3",
      fixed = TRUE
    )
  }
})

test_that("device proof errors never downgrade to a legacy install session", {
  local_knhanesget_config()
  knhanesget:::kng_write_private_file(
    "KNHLIC3.saved-license",
    knhanesget:::kng_license_path()
  )
  knhanesget:::kng_write_private_file(
    "KNHREQ3.abcdefghijklmnopqrstuvwxyz012345",
    knhanesget:::kng_license_request_path()
  )
  knhanesget:::kng_write_private_file(
    "0.1.0.12",
    knhanesget:::kng_license_request_version_path()
  )
  knhanesget:::kng_installation_id()
  knhanesget:::kng_device_signing_key()
  knhanesget:::kng_device_encryption_key()
  legacy_calls <- 0L
  local_mocked_bindings(
    kng_device_install_session = function(release) {
      stop(
        "The knhanes authorization server requires registered device proof.",
        call. = FALSE
      )
    },
    kng_licensed_install_session = function(release, license_code) {
      legacy_calls <<- legacy_calls + 1L
      stop("legacy install session must not run")
    },
    .package = "knhanesget"
  )

  release <- knhanesget:::kng_server_release_metadata("0.1.0.13")
  expect_error(
    knhanesget:::kng_authorize_server_release(release),
    "requires registered device proof",
    fixed = TRUE
  )
  expect_identical(legacy_calls, 0L)
})

test_that("approved device completes challenge and decrypts its activation envelope", {
  local_knhanesget_config()
  request_code <- "KNHREQ3.abcdefghijklmnopqrstuvwxyz012345"
  knhanesget:::kng_write_private_file(
    request_code,
    knhanesget:::kng_license_request_path()
  )
  knhanesget:::kng_write_private_file(
    "0.1.0.13",
    knhanesget:::kng_license_request_version_path()
  )
  knhanesget:::kng_installation_id()
  signing_key <- knhanesget:::kng_device_signing_key()
  encryption_key <- knhanesget:::kng_device_encryption_key()
  license_code <- "KNHLIC3.payload.signature"
  envelope <- knhanesget:::kng_base64url_encode(sodium::simple_encrypt(
    charToRaw(license_code),
    sodium::pubkey(encryption_key)
  ))
  calls <- list()
  local_mocked_bindings(
    kng_server_nonce = function() "device-session-nonce",
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
      if (identical(path, "/v1/device-challenges")) {
        return(list(
          challenge_id = "challenge-id-1234",
          challenge = "abcdefghijklmnopqrstuvwx",
          version = "0.1.0.13"
        ))
      }
      list(
        access_token = "short-lived-device-token",
        token_type = "bearer",
        expires_in = 300L,
        version = "0.1.0.13",
        activation_envelope = envelope
      )
    },
    .package = "knhanesget"
  )

  release <- knhanesget:::kng_server_release_metadata("0.1.0.13")
  authorized <- knhanesget:::kng_authorize_server_release(release)

  expect_length(calls, 2L)
  expect_identical(calls[[1L]]$path, "/v1/device-challenges")
  expect_identical(
    names(calls[[1L]]$body),
    c(
      "request_code",
      "version",
      "installation_id",
      "nonce",
      "signature"
    )
  )
  challenge_body <- calls[[1L]]$body
  challenge_canonical <- knhanesget:::kng_device_signature_message(
    "knhanes-device-challenge-request-v1",
    "https://api.knhanesr.com",
    challenge_body$installation_id,
    knhanesget:::kng_public_key_fingerprint(
      sodium::sig_pubkey(signing_key)
    ),
    knhanesget:::kng_public_key_fingerprint(
      sodium::pubkey(encryption_key)
    ),
    challenge_body$request_code,
    challenge_body$version,
    challenge_body$nonce
  )
  expect_identical(sum(challenge_canonical == as.raw(0L)), 7L)
  expect_true(sodium::sig_verify(
    challenge_canonical,
    knhanesget:::kng_base64url_decode(challenge_body$signature),
    sodium::sig_pubkey(signing_key)
  )
  )
  expect_identical(calls[[2L]]$path, "/v1/device-install-sessions")
  expect_identical(calls[[2L]]$method, "POST")
  expect_identical(calls[[2L]]$expected_status, 201L)
  expect_identical(
    names(calls[[2L]]$body),
    c(
      "request_code",
      "version",
      "challenge_id",
      "challenge",
      "nonce",
      "signature"
    )
  )
  session_body <- calls[[2L]]$body
  canonical <- knhanesget:::kng_device_signature_message(
    "knhanes-device-install-session-v1",
    "https://api.knhanesr.com",
    knhanesget:::kng_installation_id(),
    knhanesget:::kng_public_key_fingerprint(
      sodium::sig_pubkey(signing_key)
    ),
    knhanesget:::kng_public_key_fingerprint(
      sodium::pubkey(encryption_key)
    ),
    session_body$request_code,
    session_body$version,
    session_body$challenge_id,
    session_body$challenge,
    session_body$nonce
  )
  expect_identical(sum(canonical == as.raw(0L)), 9L)
  expect_true(sodium::sig_verify(
    canonical,
    knhanesget:::kng_base64url_decode(session_body$signature),
    sodium::sig_pubkey(signing_key)
  ))
  expect_identical(authorized$access_token, "short-lived-device-token")
  expect_identical(authorized$activation_license_code, license_code)
  expect_false(any(grepl(
    "KNHLIC3|device-signing-key|device-encryption-key",
    unlist(session_body, use.names = FALSE),
    fixed = FALSE
  )))
})

test_that("device challenge must bind the exact release version", {
  local_knhanesget_config()
  knhanesget:::kng_write_private_file(
    "KNHREQ3.abcdefghijklmnopqrstuvwxyz012345",
    knhanesget:::kng_license_request_path()
  )
  knhanesget:::kng_write_private_file(
    "0.1.0.13",
    knhanesget:::kng_license_request_version_path()
  )
  knhanesget:::kng_installation_id()
  knhanesget:::kng_device_signing_key()
  knhanesget:::kng_device_encryption_key()
  calls <- 0L
  local_mocked_bindings(
    kng_server_request_json = function(path,
                                       method = "GET",
                                       body = NULL,
                                       expected_status = 200L) {
      calls <<- calls + 1L
      list(
        challenge_id = "challenge-id-1234",
        challenge = "abcdefghijklmnopqrstuvwx",
        version = "0.1.0.12"
      )
    },
    .package = "knhanesget"
  )

  release <- knhanesget:::kng_server_release_metadata("0.1.0.13")
  expect_error(
    knhanesget:::kng_authorize_server_release(release),
    "invalid device challenge"
  )
  expect_identical(calls, 1L)
})

test_that("activation envelopes cannot be opened by a different device", {
  local_knhanesget_config()
  wrong_key <- sodium::keygen()
  envelope <- knhanesget:::kng_base64url_encode(sodium::simple_encrypt(
    charToRaw("KNHLIC3.payload.signature"),
    sodium::pubkey(wrong_key)
  ))
  expect_error(
    knhanesget:::kng_decrypt_activation_envelope(envelope),
    "could not be authenticated for this device"
  )
})

test_that("device installation requires a saved approved request", {
  local_knhanesget_config()
  release <- knhanesget:::kng_server_release_metadata("0.1.0.13")
  expect_error(
    knhanesget:::kng_authorize_server_release(release),
    "registered knhanes license request was not found"
  )
})

test_that("missing registered device keys are not silently regenerated", {
  local_knhanesget_config()
  knhanesget:::kng_installation_id()
  knhanesget:::kng_write_private_file(
    "KNHREQ3.abcdefghijklmnopqrstuvwxyz012345",
    knhanesget:::kng_license_request_path()
  )
  knhanesget:::kng_write_private_file(
    "0.1.0.13",
    knhanesget:::kng_license_request_version_path()
  )
  release <- knhanesget:::kng_server_release_metadata("0.1.0.13")

  expect_error(
    knhanesget:::kng_authorize_server_release(release),
    "deactivate_device"
  )
  expect_false(file.exists(knhanesget:::kng_device_signing_key_path()))
  expect_false(file.exists(knhanesget:::kng_device_encryption_key_path()))
})

test_that("approved request version does not pin later device updates", {
  local_knhanesget_config()
  knhanesget:::kng_write_private_file(
    "KNHREQ3.abcdefghijklmnopqrstuvwxyz012345",
    knhanesget:::kng_license_request_path()
  )
  knhanesget:::kng_write_private_file(
    "0.1.0.12",
    knhanesget:::kng_license_request_version_path()
  )
  knhanesget:::kng_write_private_file(
    "KNHLIC3.saved-license",
    knhanesget:::kng_license_path()
  )
  knhanesget:::kng_installation_id()
  knhanesget:::kng_device_signing_key()
  knhanesget:::kng_device_encryption_key()
  seen_versions <- character()
  local_mocked_bindings(
    kng_device_install_session = function(release) {
      seen_versions <<- c(seen_versions, release$version)
      list(
        access_token = "later-version-token",
        token_type = "bearer",
        version = release$version,
        activation_envelope = "later-version-envelope"
      )
    },
    kng_licensed_install_session = function(release, license_code) {
      stop("legacy install session must not run")
    },
    kng_decrypt_activation_envelope = function(envelope) {
      "KNHLIC3.updated-license"
    },
    .package = "knhanesget"
  )
  release <- knhanesget:::kng_server_release_metadata("0.1.0.13")

  authorized <- knhanesget:::kng_authorize_server_release(release)
  expect_identical(seen_versions, "0.1.0.13")
  expect_identical(authorized$version, "0.1.0.13")
  expect_identical(authorized$access_token, "later-version-token")
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
  expect_error(
    knhanesget:::kng_download_headers(),
    "short-lived install session access token is required",
    fixed = TRUE
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
