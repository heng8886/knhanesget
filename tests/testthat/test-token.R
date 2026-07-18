test_that("getToken creates a stable compact compatible request", {
  local_knhanesget_config()
  withr::local_options(knhanesget.username_test = "henry")
  first <- getToken(version = "0.1.0.4", quiet = TRUE)
  second <- getToken(version = "0.1.0.4", quiet = TRUE)

  expect_identical(first, second)
  expect_match(first, "^KNHREQ2\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]{8}$")
  expect_lt(nchar(first), 80L)
  body <- decode_request_body(first)
  expect_length(body, 16L + nchar("0.1.0.4\nhenry"))
  expect_match(sodium::bin2hex(body[seq_len(16L)]), "^[0-9a-f]{32}$")
  expect_identical(rawToChar(body[-seq_len(16L)]), "0.1.0.4\nhenry")
  expect_true(file.exists(knhanesget:::kng_installation_path()))
})

test_that("getToken includes username but not hostname", {
  local_knhanesget_config()
  withr::local_options(knhanesget.username_test = "test-user")
  body <- decode_request_body(getToken(version = "0.1.0.4", quiet = TRUE))
  metadata <- rawToChar(body[-seq_len(16L)])
  expect_match(metadata, "test-user", fixed = TRUE)
  expect_false(grepl(Sys.info()[["nodename"]], metadata, fixed = TRUE))
})

test_that("getToken prints the current contact instructions", {
  local_knhanesget_config()
  withr::local_options(knhanesget.username_test = "henry")
  output <- capture.output(getToken(version = "0.1.0.4"))
  expect_true(any(grepl("请将完整申请码和姓名发送给我。", output, fixed = TRUE)))
  expect_true(any(grepl("邮箱：henry88866@163.com", output, fixed = TRUE)))
  expect_false(any(grepl("install_knhanes", output, fixed = TRUE)))
})

test_that("getToken validates arguments", {
  local_knhanesget_config()
  expect_error(getToken(version = "latest", quiet = TRUE), "dot-separated")
  expect_error(getToken(version = "0.1.0.4", quiet = NA), "TRUE or FALSE")
})

test_that("getToken keeps long username requests on one line", {
  local_knhanesget_config()
  withr::local_options(knhanesget.username_test = strrep("a", 100L))
  code <- getToken(version = "0.1.0.4", quiet = TRUE)
  expect_false(grepl("[\r\n]", code))
  expect_match(code, "^KNHREQ2\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]{8}$")
})
