test_that("shared Unicode registration fixture matches canonical bytes and signatures", {
  fixture <- jsonlite::read_json(
    testthat::test_path("fixtures", "canonical-v1-unicode.json"),
    simplifyVector = FALSE
  )

  expect_identical(
    fixture$schema,
    "knhanes-canonical-v1-unicode-fixture"
  )
  expect_identical(fixture$fixture_version, 1L)
  expect_identical(fixture$algorithm, "Ed25519")

  registration <- fixture$registration
  expect_identical(
    registration$protocol_domain,
    "knhanes-device-registration-v1"
  )
  expect_identical(
    registration$api_identity,
    knhanesget:::.kng_default_server_base_url
  )

  signing_seed <- sodium::hex2bin(fixture$signing_seed_hex)
  signing_key <- sodium::sig_keygen(signing_seed)
  signing_public_key <- knhanesget:::kng_base64url_encode(
    sodium::sig_pubkey(signing_key)
  )
  expect_identical(
    signing_public_key,
    registration$signing_public_key
  )

  canonical_messages <- list()
  canonical_signatures <- list()
  for (case in registration$cases) {
    actual_codepoints <- sprintf(
      "U+%04X",
      utf8ToInt(enc2utf8(case$username))
    )
    expect_identical(
      actual_codepoints,
      unlist(case$username_codepoints, use.names = FALSE),
      info = case$name
    )

    message <- knhanesget:::kng_device_signature_message(
      registration$protocol_domain,
      registration$api_identity,
      registration$installation_id,
      registration$version,
      case$username,
      registration$signing_public_key,
      registration$encryption_public_key,
      registration$nonce
    )
    signature <- knhanesget:::kng_base64url_encode(
      sodium::sig_sign(message, signing_key)
    )

    expect_identical(
      sodium::bin2hex(message),
      case$expected_canonical_hex,
      info = case$name
    )
    expect_identical(
      sodium::bin2hex(sodium::sha256(message)),
      case$expected_sha256,
      info = case$name
    )
    expect_identical(
      signature,
      case$expected_signature_base64url,
      info = case$name
    )
    expect_true(sodium::sig_verify(
      message,
      knhanesget:::kng_base64url_decode(signature),
      sodium::sig_pubkey(signing_key)
    ))

    canonical_messages[[case$name]] <- message
    canonical_signatures[[case$name]] <- signature
  }

  expect_false(identical(
    canonical_messages$nfd,
    canonical_messages$nfc
  ))
  expect_false(identical(
    canonical_signatures$nfd,
    canonical_signatures$nfc
  ))
})
