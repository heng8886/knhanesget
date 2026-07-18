test_that("test configuration remains isolated for the full test scope", {
  real_config <- tools::R_user_dir("knhanes", which = "config")
  test_config <- local_knhanesget_config()

  expect_identical(getOption("knhanesget.config_dir_test"), test_config)
  expect_identical(knhanesget:::kng_config_dir(), test_config)
  expect_false(identical(normalizePath(test_config), normalizePath(real_config)))
})
