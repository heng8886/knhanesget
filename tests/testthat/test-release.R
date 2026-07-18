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
    tag_name = "v0.1.0.3",
    html_url = "https://example.test/release",
    assets = list(
      list(
        name = "knhanes_0.1.0.3.tar.gz",
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
  version <- "0.1.0.3"
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
  expect_identical(result$tag, "v0.1.0.3")
  expect_true(endsWith(result$signature_url, ".sig"))
})
