#' 生成 knhanes 安装授权申请码
#'
#' 在安装knhanes之前生成与其授权系统完全兼容的`KNHREQ1`申请码。申请码使用
#' 随机安装实例ID，不读取CPU、BIOS、MAC地址、主机名或用户名。
#'
#' @param version 申请安装的knhanes版本。若为`NULL`，优先使用已安装版本；若尚未
#'   安装，则尝试读取最新GitHub Release，网络不可用时回退到辅助包内置兼容版本。
#' @param quiet 逻辑值。若为`FALSE`，显示申请码和发送说明；若为`TRUE`，只返回
#'   申请码。
#'
#' @details
#' 随机安装ID保存在R用户级knhanes配置目录。正常更新或重装R包不会改变该ID，
#' 因此已签发授权可以继续使用。申请码只包含包名、随机安装ID、目标版本和校验值，
#' 不包含KNHANES数据、GitHub令牌或授权私钥。
#'
#' @return 隐式返回以`KNHREQ1.`开头的申请码字符串。
#' @export
#'
#' @examples
#' \dontrun{
#' request_code <- getToken(quiet = TRUE)
#' }
getToken <- function(version = NULL, quiet = FALSE) {
  kng_scalar_logical(quiet, "quiet")
  if (is.null(version)) {
    version <- kng_installed_version()
    if (is.na(version)) {
      version <- tryCatch(
        kng_release_metadata("latest")$version,
        error = function(e) .kng_fallback_version
      )
    }
  }
  version <- kng_normalize_version(version)
  body <- paste(.kng_package, kng_installation_id(), version, sep = "|")
  checksum <- substr(
    sodium::bin2hex(sodium::sha256(charToRaw(body))),
    1L,
    16L
  )
  code <- paste(
    "KNHREQ1",
    sodium::bin2hex(charToRaw(body)),
    checksum,
    sep = "."
  )
  if (!quiet) {
    cat(
      "knhanes \u6388\u6743\u7533\u8bf7\u7801\uff1a\n",
      code,
      "\n\n\u8bf7\u5c06\u5b8c\u6574\u7533\u8bf7\u7801\u548c\u59d3\u540d\u53d1\u9001\u81f3 ",
      .kng_contact,
      "\u3002\n\u6536\u5230 KNHLIC2 \u6388\u6743\u7801\u540e\uff0c\u8fd0\u884c ",
      "install_knhanes(license_code = \"\u6388\u6743\u7801\")\u3002\n",
      sep = ""
    )
  }
  invisible(code)
}
