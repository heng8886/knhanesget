test_that("same installed version is activated without reinstalling", {
  lib <- tempfile("knhanesget-lib-")
  dir.create(lib)
  activated <- NULL
  authorized <- 0L
  local_mocked_bindings(
    kng_local_license_code = function(license_code = NULL, required = TRUE) {
      NULL
    },
    kng_use_device_authorization = function(license_code = NULL,
                                            local_license = NULL) {
      TRUE
    },
    kng_server_release_metadata = function(version = "latest") {
      list(
        version = "0.1.0.13",
        activation_license_code = NULL
      )
    },
    kng_installed_version = function(lib = NULL) "0.1.0.13",
    kng_authorize_server_release = function(release, license_code = NULL) {
      authorized <<- authorized + 1L
      release$activation_license_code <- "KNHLIC3.payload.signature"
      release
    },
    kng_activate_installed_license = function(license_code, lib = NULL) {
      activated <<- list(license_code = license_code, lib = lib)
      invisible(TRUE)
    },
    kng_download_release_assets = function(...) {
      stop("download must not run")
    },
    kng_install_missing_dependencies = function(...) {
      stop("dependency installation must not run")
    },
    license_status = function(lib = NULL) {
      tibble::tibble(
        Installed = TRUE,
        Installed_version = "0.1.0.13",
        Licensed = TRUE,
        Status = "Licensed"
      )
    },
    .package = "knhanesget"
  )

  status <- install_knhanes(
    version = "0.1.0.13",
    quiet = TRUE,
    lib = lib
  )

  expect_identical(authorized, 1L)
  expect_identical(
    activated,
    list(
      license_code = "KNHLIC3.payload.signature",
      lib = lib
    )
  )
  expect_true(status$Licensed[[1L]])
})

test_that("first passwordless install keeps its approved request version", {
  lib <- tempfile("knhanesget-lib-")
  dir.create(lib)
  metadata_version <- NULL
  local_mocked_bindings(
    kng_local_license_code = function(license_code = NULL, required = TRUE) {
      NULL
    },
    kng_use_device_authorization = function(license_code = NULL,
                                            local_license = NULL) {
      TRUE
    },
    kng_saved_license_request_version = function(required = TRUE) {
      "0.1.0.12"
    },
    kng_server_release_metadata = function(version = "latest") {
      metadata_version <<- version
      list(
        version = "0.1.0.12",
        activation_license_code = NULL
      )
    },
    kng_installed_version = function(lib = NULL) NA_character_,
    kng_authorize_server_release = function(release, license_code = NULL) {
      stop("approval check reached", call. = FALSE)
    },
    kng_download_release_assets = function(...) {
      stop("download must not run")
    },
    .package = "knhanesget"
  )

  expect_error(
    install_knhanes(
      version = "latest",
      quiet = TRUE,
      lib = lib
    ),
    "approval check reached",
    fixed = TRUE
  )
  expect_identical(metadata_version, "0.1.0.12")
})

test_that("same-version annual renewal uses device proof and activates new envelope", {
  lib <- tempfile("knhanesget-lib-")
  dir.create(lib)
  activated <- NULL
  authorized <- 0L
  metadata_version <- NULL
  local_mocked_bindings(
    kng_local_license_code = function(license_code = NULL, required = TRUE) {
      "KNHLIC3.saved-license"
    },
    kng_use_device_authorization = function(license_code = NULL,
                                            local_license = NULL) {
      expect_identical(local_license, "KNHLIC3.saved-license")
      TRUE
    },
    kng_saved_license_request_version = function(required = TRUE) {
      stop("saved request version must not pin an activated update")
    },
    kng_server_release_metadata = function(version = "latest") {
      metadata_version <<- version
      list(
        version = "0.1.0.13",
        activation_license_code = NULL
      )
    },
    kng_installed_version = function(lib = NULL) "0.1.0.13",
    kng_authorize_server_release = function(release, license_code = NULL) {
      authorized <<- authorized + 1L
      release$activation_license_code <- "KNHLIC3.updated-license"
      release
    },
    kng_activate_installed_license = function(license_code, lib = NULL) {
      activated <<- license_code
      invisible(TRUE)
    },
    kng_download_release_assets = function(...) {
      stop("download must not run")
    },
    license_status = function(lib = NULL) {
      tibble::tibble(
        Installed = TRUE,
        Installed_version = "0.1.0.13",
        Licensed = TRUE,
        Status = "Licensed"
      )
    },
    .package = "knhanesget"
  )

  status <- install_knhanes(
    version = "latest",
    quiet = TRUE,
    lib = lib
  )

  expect_identical(metadata_version, "latest")
  expect_identical(authorized, 1L)
  expect_identical(activated, "KNHLIC3.updated-license")
  expect_true(status$Licensed[[1L]])
})

test_that("activated device update targets latest release, not request version", {
  lib <- tempfile("knhanesget-lib-")
  dir.create(lib)
  metadata_version <- NULL
  authorized_version <- NULL
  local_mocked_bindings(
    kng_local_license_code = function(license_code = NULL, required = TRUE) {
      "KNHLIC3.saved-license"
    },
    kng_use_device_authorization = function(license_code = NULL,
                                            local_license = NULL) {
      TRUE
    },
    kng_saved_license_request_version = function(required = TRUE) {
      stop("saved request version must not pin an activated update")
    },
    kng_server_release_metadata = function(version = "latest") {
      metadata_version <<- version
      list(
        version = "0.1.0.14",
        activation_license_code = NULL
      )
    },
    kng_installed_version = function(lib = NULL) "0.1.0.13",
    kng_authorize_server_release = function(release, license_code = NULL) {
      authorized_version <<- release$version
      stop("latest release authorization reached", call. = FALSE)
    },
    kng_download_release_assets = function(...) {
      stop("download must not run")
    },
    .package = "knhanesget"
  )

  expect_error(
    install_knhanes(
      version = "latest",
      quiet = TRUE,
      lib = lib
    ),
    "latest release authorization reached",
    fixed = TRUE
  )
  expect_identical(metadata_version, "latest")
  expect_identical(authorized_version, "0.1.0.14")
})

test_that("pending approval aborts before any package download", {
  lib <- tempfile("knhanesget-lib-")
  dir.create(lib)
  local_mocked_bindings(
    kng_local_license_code = function(license_code = NULL, required = TRUE) {
      NULL
    },
    kng_use_device_authorization = function(license_code = NULL,
                                            local_license = NULL) {
      TRUE
    },
    kng_server_release_metadata = function(version = "latest") {
      list(
        version = "0.1.0.13",
        activation_license_code = NULL
      )
    },
    kng_installed_version = function(lib = NULL) NA_character_,
    kng_authorize_server_release = function(release, license_code = NULL) {
      stop(
        "The knhanes license request is pending approval.",
        call. = FALSE
      )
    },
    kng_download_release_assets = function(...) {
      stop("download must not run")
    },
    .package = "knhanesget"
  )

  expect_error(
    install_knhanes(
      version = "0.1.0.13",
      quiet = TRUE,
      lib = lib
    ),
    "pending approval"
  )
  expect_false(dir.exists(file.path(lib, "knhanes")))
})
