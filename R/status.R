#' 查看 knhanes 版本
#'
#' 比较当前安装版本与发布仓库中的最新正式版本。
#'
#' @param check_remote 逻辑值。是否访问GitHub Release检查最新版本。
#' @param lib 可选R库目录；`NULL`表示按当前`.libPaths()`查找。
#'
#' @return 一行tibble，包含是否已安装、当前版本、最新版本、是否可更新和Release标签。
#' @export
knhanes_version <- function(check_remote = TRUE, lib = NULL) {
  kng_scalar_logical(check_remote, "check_remote")
  if (!is.null(lib)) {
    kng_scalar_character(lib, "lib")
    lib <- path.expand(lib)
  }
  installed <- kng_installed_version(lib)
  latest <- NA_character_
  release_tag <- NA_character_
  check_status <- "Not checked"
  if (check_remote) {
    release <- tryCatch(kng_release_metadata("latest"), error = identity)
    if (inherits(release, "error")) {
      check_status <- paste0("Unavailable: ", conditionMessage(release))
    } else {
      latest <- release$version
      release_tag <- release$tag
      check_status <- "OK"
    }
  }
  update_available <- if (is.na(installed) || is.na(latest)) {
    NA
  } else {
    utils::compareVersion(installed, latest) < 0L
  }
  tibble::tibble(
    Installed = !is.na(installed),
    Installed_version = installed,
    Latest_version = latest,
    Update_available = update_available,
    Release_tag = release_tag,
    Check_status = check_status
  )
}

#' 查看 knhanes 本地授权状态
#'
#' 若knhanes已经安装，调用其官方授权检查并附加安装版本；尚未安装时返回
#' `Installed = FALSE`和`Not installed`状态。
#'
#' @inheritParams knhanes_version
#'
#' @return 一行tibble。安装后包含knhanes官方授权状态字段；未安装时返回最小状态表。
#' @export
license_status <- function(lib = NULL) {
  if (!is.null(lib)) {
    kng_scalar_character(lib, "lib")
    lib <- path.expand(lib)
  }
  version <- kng_installed_version(lib)
  if (is.na(version)) {
    return(tibble::tibble(
      Installed = FALSE,
      Version = NA_character_,
      Licensed = FALSE,
      Status = "Not installed",
      License_type = NA_character_,
      Entitlement_status = "Not activated"
    ))
  }
  ns <- loadNamespace("knhanes", lib.loc = lib)
  status_fun <- getExportedValue("knhanes", "knh_license_status")
  status <- status_fun()
  tibble::add_column(
    tibble::as_tibble(status),
    Installed = TRUE,
    Version = version,
    .before = 1L
  )
}

#' 删除本地 knhanes 授权
#'
#' 删除当前用户配置目录中的knhanes授权文件。可选择同时重置随机安装ID；重置后
#' 原授权码将不能在此安装实例继续使用，必须重新申请。
#'
#' @param confirm 为防止误操作，必须明确设为`TRUE`。
#' @param reset_installation_id 是否同时删除随机安装ID。默认`FALSE`，普通反激活
#'   仍保留稳定申请码；设为`TRUE`后下次[getToken()]会生成新ID。
#'
#' @return 隐式返回一行tibble，说明是否删除授权和重置安装ID。
#' @export
deactivate_device <- function(confirm = FALSE,
                              reset_installation_id = FALSE) {
  kng_scalar_logical(confirm, "confirm")
  kng_scalar_logical(reset_installation_id, "reset_installation_id")
  if (!confirm) {
    stop("Set confirm = TRUE to remove the local knhanes license.",
         call. = FALSE)
  }
  license_path <- kng_license_path()
  installation_path <- kng_installation_path()
  license_removed <- if (file.exists(license_path)) {
    unlink(license_path) == 0L
  } else {
    FALSE
  }
  installation_reset <- FALSE
  if (reset_installation_id && file.exists(installation_path)) {
    installation_reset <- unlink(installation_path) == 0L
  }
  result <- tibble::tibble(
    License_removed = license_removed,
    Installation_ID_reset = installation_reset,
    Config_dir = kng_config_dir()
  )
  if (license_removed) {
    message("The local knhanes license was removed.")
  }
  if (installation_reset) {
    message("The knhanes installation ID was reset; request a new license.")
  }
  invisible(result)
}
