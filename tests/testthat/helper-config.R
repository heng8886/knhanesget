local_knhanesget_config <- function() {
  path <- tempfile("knhanesget-config-")
  dir.create(path)
  withr::local_options(knhanesget.config_dir_test = path)
  withr::defer(unlink(path, recursive = TRUE), envir = parent.frame())
  path
}

decode_request_body <- function(code) {
  parts <- strsplit(code, ".", fixed = TRUE)[[1L]]
  rawToChar(sodium::hex2bin(parts[[2L]]))
}

