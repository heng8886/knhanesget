test_that("getToken creates a stable compatible request", {
  local_knhanesget_config()
  first <- getToken(version = "0.1.0.3", quiet = TRUE)
  second <- getToken(version = "0.1.0.3", quiet = TRUE)

  expect_identical(first, second)
  expect_match(first, "^KNHREQ1\\.[0-9a-f]+\\.[0-9a-f]{16}$")
  body <- decode_request_body(first)
  fields <- strsplit(body, "|", fixed = TRUE)[[1L]]
  expect_identical(fields[[1L]], "knhanes")
  expect_match(fields[[2L]], "^[0-9a-f]{32}$")
  expect_identical(fields[[3L]], "0.1.0.3")
  expect_true(file.exists(knhanesget:::kng_installation_path()))
})

test_that("getToken does not expose local hardware labels", {
  local_knhanesget_config()
  body <- decode_request_body(getToken(version = "0.1.0.3", quiet = TRUE))
  expect_false(grepl(Sys.info()[["nodename"]], body, fixed = TRUE))
  expect_false(grepl(Sys.info()[["user"]], body, fixed = TRUE))
})

test_that("getToken validates arguments", {
  local_knhanesget_config()
  expect_error(getToken(version = "latest", quiet = TRUE), "dot-separated")
  expect_error(getToken(version = "0.1.0.3", quiet = NA), "TRUE or FALSE")
})

