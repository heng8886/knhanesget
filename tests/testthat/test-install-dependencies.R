test_that("dependency names are parsed from DESCRIPTION fields", {
  fields <- c(
    "R (>= 4.1), dplyr (>= 1.0.0), readr",
    "survey, dplyr, rlang (>= 1.1.0)",
    NA_character_
  )

  expect_identical(
    knhanesget:::kng_dependency_names(fields),
    c("dplyr", "readr", "survey", "rlang")
  )
  expect_identical(knhanesget:::kng_dependency_names(NA_character_), character())
})

test_that("archive dependencies are read from the packaged DESCRIPTION", {
  root <- tempfile("fake-package-")
  package_dir <- file.path(root, "fakepkg")
  dir.create(package_dir, recursive = TRUE)
  writeLines(
    c(
      "Package: fakepkg",
      "Version: 0.0.1",
      "Depends: R (>= 4.1), alpha",
      "Imports: beta (>= 1.0), gamma",
      "LinkingTo: delta"
    ),
    file.path(package_dir, "DESCRIPTION")
  )
  archive <- tempfile(fileext = ".tar.gz")
  old <- setwd(root)
  on.exit(setwd(old), add = TRUE)
  on.exit(unlink(root, recursive = TRUE), add = TRUE)
  on.exit(unlink(archive), add = TRUE)
  utils::tar(archive, files = "fakepkg", compression = "gzip")

  expect_identical(
    knhanesget:::kng_archive_dependencies(archive, tempfile("extract-")),
    c("alpha", "beta", "gamma", "delta")
  )
})

test_that("CRAN repository fallback is portable and preserves explicit mirrors", {
  old <- options(repos = c(CRAN = "@CRAN@"))
  on.exit(options(old), add = TRUE)
  expect_identical(
    unname(knhanesget:::kng_cran_repositories()[["CRAN"]]),
    "https://cloud.r-project.org"
  )

  options(repos = c(CRAN = "https://example.invalid/cran"))
  expect_identical(
    unname(knhanesget:::kng_cran_repositories()[["CRAN"]]),
    "https://example.invalid/cran"
  )
})

test_that("invalid archives fail before dependency installation", {
  root <- tempfile("bad-package-")
  dir.create(root)
  writeLines("not a package", file.path(root, "README"))
  archive <- tempfile(fileext = ".tar.gz")
  old <- setwd(root)
  on.exit(setwd(old), add = TRUE)
  on.exit(unlink(root, recursive = TRUE), add = TRUE)
  on.exit(unlink(archive), add = TRUE)
  utils::tar(archive, files = "README", compression = "gzip")

  expect_error(
    knhanesget:::kng_archive_dependencies(archive, tempfile("extract-")),
    "exactly one package DESCRIPTION",
    fixed = TRUE
  )
})
