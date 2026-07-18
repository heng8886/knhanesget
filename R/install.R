#' 安装或更新 knhanes
#'
#' 从维护者发布仓库下载指定knhanes版本，验证SHA-256与Ed25519发布签名后安装。
#' 首次安装可同时提供`KNHLIC3`授权码完成激活；老用户更新时无需重复输入授权码。
#'
#' @param license_code 首次激活使用的完整knhanes授权码，新版通常以`KNHLIC3.`开头。
#'   旧`KNHLIC1.`和`KNHLIC2.`授权码仍可使用。
#'   已激活用户更新时设为`NULL`即可。
#' @param version 要安装的版本。默认`"latest"`安装最新正式Release；也可指定
#'   如`"0.1.0.4"`或`"v0.1.0.4"`。
#' @param force 逻辑值。若为`TRUE`，即使同版本已经安装也重新安装。
#' @param quiet 逻辑值。是否减少下载和安装过程输出。
#' @param lib 安装R包的库目录。默认使用`.libPaths()`中的第一个目录。
#'
#' @details
#' 发布包、校验文件和签名来自`heng8886/knhanes-dist`的版本化GitHub Release。
#' 本函数不需要GitHub账号或PAT。校验通过后会读取发布包的`DESCRIPTION`，
#' 使用当前CRAN镜像自动安装尚未安装的`Depends`、`Imports`和`LinkingTo`依赖，
#' 然后才安装knhanes；若当前未配置CRAN镜像，则使用
#' `https://cloud.r-project.org`。因此Windows和macOS用户通常无需预先手工安装依赖。
#' 授权保存在R用户配置目录，正常更新不会删除。若knhanes已经在当前R会话加载，
#' 更新后建议重启R再使用新版本。
#'
#' @return 隐式返回[license_status()]的一行tibble。
#' @export
#'
#' @examples
#' \dontrun{
#' install_knhanes(license_code = "KNHLIC3.<payload>.<signature>")
#' install_knhanes()
#' }
install_knhanes <- function(license_code = NULL,
                            version = "latest",
                            force = FALSE,
                            quiet = FALSE,
                            lib = .libPaths()[1L]) {
  if (!is.null(license_code)) {
    kng_scalar_character(license_code, "license_code")
  }
  kng_scalar_character(version, "version")
  kng_scalar_logical(force, "force")
  kng_scalar_logical(quiet, "quiet")
  kng_scalar_character(lib, "lib")
  lib <- path.expand(lib)
  if (!dir.exists(lib)) {
    dir.create(lib, recursive = TRUE, showWarnings = FALSE)
  }
  if (!dir.exists(lib) || file.access(lib, 2L) != 0L) {
    stop("The R library is not writable: ", lib, call. = FALSE)
  }

  was_loaded <- isNamespaceLoaded("knhanes")
  release <- kng_release_metadata(version)
  installed_before <- kng_installed_version(lib)
  needs_install <- isTRUE(force) || is.na(installed_before) ||
    !identical(installed_before, release$version)

  if (needs_install) {
    work <- tempfile("knhanesget-release-")
    dir.create(work)
    on.exit(unlink(work, recursive = TRUE), add = TRUE)
    archive <- file.path(work, release$archive_name)
    checksum <- paste0(archive, ".sha256")
    signature <- paste0(archive, ".sig")
    kng_download(release$archive_url, archive, quiet = quiet)
    kng_download(release$checksum_url, checksum, quiet = quiet)
    kng_download(release$signature_url, signature, quiet = quiet)
    kng_verify_archive(archive, checksum, signature)
    if (!quiet) {
      message(
        "knhanes v", release$version,
        " archive verified (SHA-256 and Ed25519 signature)."
      )
    }
    dependencies <- kng_archive_dependencies(
      archive,
      file.path(work, "archive-description")
    )
    kng_install_missing_dependencies(
      dependencies,
      lib = lib,
      quiet = quiet
    )
    utils::install.packages(
      archive,
      repos = NULL,
      type = "source",
      lib = lib,
      quiet = quiet
    )
  } else if (!quiet) {
    message("knhanes v", release$version, " is already installed.")
  }

  installed_after <- kng_installed_version(lib)
  if (!identical(installed_after, release$version)) {
    stop(
      "knhanes installation did not produce the expected version ",
      release$version,
      ".",
      call. = FALSE
    )
  }

  if (!is.null(license_code)) {
    ns <- loadNamespace("knhanes", lib.loc = lib)
    activate <- getExportedValue("knhanes", "knh_activate")
    suppressMessages(activate(trimws(license_code)))
  }
  status <- license_status(lib = lib)
  if (!isTRUE(status$Licensed[[1L]])) {
    message(
      "knhanes v", release$version,
      " is installed but not activated. Run getToken(), obtain a license, ",
      "then rerun install_knhanes(license_code = \"...\")."
    )
  } else if (!quiet) {
    message(
      "knhanes v", release$version,
      " is installed and the local license is active."
    )
  }
  if (was_loaded && needs_install && !quiet) {
    message("Restart R before using the updated knhanes version.")
  }
  invisible(status)
}

kng_dependency_names <- function(fields) {
  fields <- fields[!is.na(fields)]
  if (!length(fields)) {
    return(character())
  }
  entries <- unlist(strsplit(paste(fields, collapse = ","), ",", fixed = TRUE))
  entries <- trimws(sub("\\s*\\([^)]*\\)\\s*$", "", entries))
  unique(entries[nzchar(entries) & entries != "R"])
}

kng_archive_dependencies <- function(archive, exdir) {
  members <- utils::untar(archive, list = TRUE)
  description <- grep("^[^/]+/DESCRIPTION$", members, value = TRUE)
  if (length(description) != 1L) {
    stop(
      "The verified knhanes archive does not contain exactly one package DESCRIPTION.",
      call. = FALSE
    )
  }
  dir.create(exdir, recursive = TRUE, showWarnings = FALSE)
  utils::untar(archive, files = description, exdir = exdir)
  dcf <- read.dcf(
    file.path(exdir, description),
    fields = c("Depends", "Imports", "LinkingTo")
  )
  kng_dependency_names(as.character(dcf[1L, ]))
}

kng_cran_repositories <- function() {
  repos <- getOption("repos")
  if (is.null(repos) || !length(repos)) {
    return(c(CRAN = "https://cloud.r-project.org"))
  }
  repos <- repos[!is.na(repos) & nzchar(repos)]
  if (!length(repos)) {
    return(c(CRAN = "https://cloud.r-project.org"))
  }
  cran <- match("CRAN", names(repos))
  if (is.na(cran)) {
    repos <- c(CRAN = "https://cloud.r-project.org", repos)
  } else if (identical(unname(repos[[cran]]), "@CRAN@")) {
    repos[[cran]] <- "https://cloud.r-project.org"
  }
  repos
}

kng_installed_package_names <- function(lib) {
  libraries <- unique(c(lib, .libPaths()))
  libraries <- libraries[dir.exists(libraries)]
  rownames(utils::installed.packages(lib.loc = libraries))
}

kng_install_missing_dependencies <- function(packages, lib, quiet = FALSE) {
  missing <- setdiff(packages, kng_installed_package_names(lib))
  if (!length(missing)) {
    return(invisible(character()))
  }
  if (!quiet) {
    message("Installing missing knhanes dependencies: ", paste(missing, collapse = ", "))
  }
  utils::install.packages(
    missing,
    repos = kng_cran_repositories(),
    lib = lib,
    dependencies = c("Depends", "Imports", "LinkingTo"),
    quiet = quiet
  )
  unresolved <- setdiff(missing, kng_installed_package_names(lib))
  if (length(unresolved)) {
    stop(
      "Unable to install required knhanes dependencies: ",
      paste(unresolved, collapse = ", "),
      ". Check the CRAN repository and network connection, then retry.",
      call. = FALSE
    )
  }
  invisible(missing)
}
