local_knhanesget_config <- function() {
  path <- tempfile("knhanesget-config-")
  dir.create(path)
  test_env <- parent.frame()
  withr::local_options(
    knhanesget.config_dir_test = path,
    .local_envir = test_env
  )
  withr::defer(unlink(path, recursive = TRUE), envir = test_env)
  path
}

decode_request_body <- function(code) {
  parts <- strsplit(code, ".", fixed = TRUE)[[1L]]
  value <- chartr("-_", "+/", parts[[2L]])
  padding <- (4L - nchar(value) %% 4L) %% 4L
  if (padding > 0L) {
    value <- paste0(value, strrep("=", padding))
  }
  jsonlite::base64_dec(value)
}
