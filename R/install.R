#' 安装或更新 knhanes
#'
#' 从官方授权服务器下载指定knhanes版本，验证SHA-256与Ed25519发布签名后安装。
#' 通过[getToken()]登记并获管理员批准后，首次安装无需手工输入授权码；老用户更新
#' 同样无需重复输入授权码。
#'
#' @param license_code 可选的完整knhanes授权码。普通在线审批流程保持默认`NULL`；
#'   管理员批准[getToken()]生成的申请后，函数会从官方服务器取得当前设备加密的
#'   激活信封并自动激活。授权服务器的显式兼容安装路径仅接受`KNHLIC3.`授权码。
#'   `KNHLIC1.`或`KNHLIC2.`若仍受已安装knhanes支持，只可用于无需服务器下载的
#'   本地激活，不作为本辅助包在线安装的兼容承诺。已激活用户更新时保持`NULL`。
#' @param version 要安装的版本。默认`"latest"`安装最新正式Release；也可指定
#'   如`"0.1.0.13"`或`"v0.1.0.13"`。
#' @param force 逻辑值。若为`TRUE`，即使同版本已经安装也重新安装。
#' @param quiet 逻辑值。是否减少下载和安装过程输出。
#' @param lib 安装R包的库目录。默认使用`.libPaths()`中的第一个目录。
#'
#' @details
#' 默认通过`https://api.knhanesr.com`创建短期安装会话，并从授权服务器下载
#' 发布包、SHA-256校验文件和Ed25519签名。只要本机保留`KNHREQ3`申请码及完整
#' 设备密钥，未显式传入`license_code`的安装和更新都必须使用本机Ed25519签名
#' 完成一次性挑战；即使knhanes已有本地授权，也不会降级为仅提交旧授权码的流程。
#' 函数使用本机Curve25519私钥解开`activation_envelope`；明文授权码只在内存中
#' 短暂存在，随后由knhanes自身验证并保存。仅显式提供`license_code`，或没有设备
#' 注册资料的既有用户，才使用兼容流程。服务器要求设备证明或设备证明失败时不会
#' 静默回退。首次尚未激活且`version = "latest"`时，函数沿用申请时保存的版本；
#' 已激活设备后续更新则重新解析最新版本，并以该精确目标版本完成挑战。授权码和
#' 短期令牌不会写入URL。
#' 校验通过后会读取发布包的`DESCRIPTION`，
#' 使用当前CRAN镜像自动安装尚未安装的`Depends`、`Imports`和`LinkingTo`依赖，
#' 然后才安装knhanes；若当前未配置CRAN镜像，则使用
#' `https://cloud.r-project.org`。因此Windows和macOS用户通常无需预先手工安装依赖。
#' 授权保存在R用户配置目录，正常更新不会删除。更新前会自动尝试卸载当前R会话中
#' 已附加或仅加载namespace的knhanes；若其他包仍依赖该namespace而无法安全卸载，
#' 函数会在安装前停止，并提示重启R后直接重新运行本函数。
#'
#' @return 隐式返回[license_status()]的一行tibble。
#' @export
#'
#' @examples
#' \dontrun{
#' getToken()
#' # 管理员批准后：
#' install_knhanes()
#' # 兼容旧流程：
#' install_knhanes(license_code = "KNHLIC3.<payload>.<signature>")
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
  local_license <- kng_local_license_code(
    license_code,
    required = FALSE
  )
  use_device_authorization <- kng_use_device_authorization(
    license_code,
    local_license
  )
  if (use_device_authorization &&
      is.null(local_license) &&
      identical(trimws(version), "latest")) {
    requested_version <- kng_saved_license_request_version(required = FALSE)
    if (!is.null(requested_version)) {
      version <- requested_version
    }
  }
  release <- kng_server_release_metadata(version)
  installed_before <- kng_installed_version(lib)
  needs_install <- isTRUE(force) || is.na(installed_before) ||
    !identical(installed_before, release$version)
  activation_code <- if (!is.null(license_code)) {
    trimws(license_code)
  } else {
    NULL
  }

  if (needs_install || use_device_authorization) {
    release <- kng_authorize_server_release(release, license_code)
    if (!is.null(release$activation_license_code)) {
      activation_code <- release$activation_license_code
    }
  }

  if (needs_install) {
    kng_prepare_package_update("knhanes", quiet = quiet)
    work <- tempfile("knhanesget-release-")
    dir.create(work)
    on.exit(unlink(work, recursive = TRUE), add = TRUE)
    assets <- kng_download_release_assets(release, work, quiet = quiet)
    archive <- assets$archive
    kng_verify_archive(archive, assets$checksum, assets$signature)
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

  if (!is.null(activation_code)) {
    kng_activate_installed_license(activation_code, lib)
  }
  status <- license_status(lib = lib)
  if (!isTRUE(status$Licensed[[1L]])) {
    message(
      "knhanes v", release$version,
      " is installed but not activated. Run getToken(), wait for approval, ",
      "then rerun install_knhanes()."
    )
  } else if (!quiet) {
    message(
      "knhanes v", release$version,
      " is installed and the local license is active."
    )
  }
  if (was_loaded && needs_install && !quiet) {
    message(
      "The previous knhanes package was unloaded before updating. ",
      "Run library(knhanes) to attach the updated version."
    )
  }
  invisible(status)
}

kng_activate_installed_license <- function(license_code, lib = NULL) {
  kng_scalar_character(license_code, "license_code")
  loadNamespace("knhanes", lib.loc = lib)
  activate <- getExportedValue("knhanes", "knh_activate")
  suppressMessages(activate(trimws(license_code)))
  invisible(TRUE)
}

kng_package_attached <- function(package) {
  paste0("package:", package) %in% search()
}

kng_namespace_loaded <- function(package) {
  isNamespaceLoaded(package)
}

kng_detach_package <- function(package) {
  detach(
    paste0("package:", package),
    unload = TRUE,
    character.only = TRUE
  )
}

kng_unload_namespace <- function(package) {
  unloadNamespace(package)
}

kng_prepare_package_update <- function(package, quiet = FALSE) {
  attached <- kng_package_attached(package)
  loaded <- kng_namespace_loaded(package)
  if (!attached && !loaded) {
    return(invisible(FALSE))
  }

  errors <- character()
  if (attached) {
    tryCatch(
      kng_detach_package(package),
      error = function(e) {
        errors <<- c(errors, conditionMessage(e))
      }
    )
  }
  if (kng_namespace_loaded(package)) {
    tryCatch(
      kng_unload_namespace(package),
      error = function(e) {
        errors <<- c(errors, conditionMessage(e))
      }
    )
  }

  if (kng_package_attached(package) || kng_namespace_loaded(package)) {
    detail <- if (length(errors)) {
      paste0(" Details: ", paste(unique(errors), collapse = "; "))
    } else {
      ""
    }
    stop(
      "The installed package '", package,
      "' is currently in use and cannot be updated safely. ",
      "Restart R, do not run library(", package, "), then rerun ",
      "knhanesget::install_knhanes().",
      detail,
      call. = FALSE
    )
  }
  if (!quiet) {
    message("Unloaded the active ", package, " package before updating.")
  }
  invisible(TRUE)
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
