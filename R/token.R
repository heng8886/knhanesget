#' 生成 knhanes 安装授权申请码
#'
#' 在安装knhanes之前生成与其授权系统完全兼容的`KNHREQ2`申请码。申请码使用
#' 随机安装实例ID，并记录操作系统当前用户名；不读取CPU、BIOS、MAC地址或主机名。
#'
#' @param version 申请安装的knhanes版本。若为`NULL`，优先使用已安装版本；若尚未
#'   安装，则尝试读取最新GitHub Release，网络不可用时回退到辅助包内置兼容版本。
#' @param quiet 逻辑值。若为`FALSE`，显示申请码和发送说明；若为`TRUE`，只返回
#'   申请码。
#'
#' @details
#' 随机安装ID保存在R用户级knhanes配置目录。正常更新或重装R包不会改变该ID，
#' 因此已签发授权可以继续使用。申请码只包含随机安装ID、目标版本、当前用户名和
#' 校验值，不包含KNHANES数据、GitHub令牌或授权私钥。`KNHREQ2`使用URL安全
#' Base64编码和紧凑二进制安装ID，比旧`KNHREQ1`十六进制格式更短。用户名仅用于
#' 帮助维护者识别申请设备，不参与授权绑定。
#'
#' @return 隐式返回以`KNHREQ2.`开头的申请码字符串。
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
  body <- c(
    sodium::hex2bin(kng_installation_id()),
    charToRaw(paste0(version, "\n", kng_local_username()))
  )
  checksum <- kng_base64url_encode(sodium::sha256(body)[seq_len(6L)])
  code <- paste(
    "KNHREQ2",
    kng_base64url_encode(body),
    checksum,
    sep = "."
  )
  if (!quiet) {
    cat(
      "knhanes \u6388\u6743\u7533\u8bf7\u7801\uff1a\n",
      code,
      "\n\n\u8bf7\u5c06\u5b8c\u6574\u7533\u8bf7\u7801\u548c\u59d3\u540d\u53d1\u9001\u7ed9\u6211\u3002",
      "\n\u90ae\u7bb1\uff1a", .kng_contact, "\n",
      sep = ""
    )
  }
  invisible(code)
}
