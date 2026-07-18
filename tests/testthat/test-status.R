test_that("license_status reports a missing installation", {
  empty_lib <- tempfile("knhanesget-lib-")
  dir.create(empty_lib)
  on.exit(unlink(empty_lib, recursive = TRUE), add = TRUE)
  status <- license_status(lib = empty_lib)
  expect_false(status$Installed[[1L]])
  expect_false(status$Licensed[[1L]])
  expect_identical(status$Status[[1L]], "Not installed")
})

test_that("deactivate_device requires confirmation", {
  local_knhanesget_config()
  expect_error(deactivate_device(), "confirm = TRUE")
})

test_that("deactivate_device removes requested local state", {
  local_knhanesget_config()
  getToken(version = "0.1.0.3", quiet = TRUE)
  writeLines("test-license", knhanesget:::kng_license_path())

  result <- deactivate_device(confirm = TRUE)
  expect_true(result$License_removed[[1L]])
  expect_false(result$Installation_ID_reset[[1L]])
  expect_true(file.exists(knhanesget:::kng_installation_path()))

  result <- deactivate_device(
    confirm = TRUE,
    reset_installation_id = TRUE
  )
  expect_true(result$Installation_ID_reset[[1L]])
  expect_false(file.exists(knhanesget:::kng_installation_path()))
})

