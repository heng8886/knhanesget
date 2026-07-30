#' 登记 knhanes 安装授权申请
#'
#' 在官方授权服务器登记当前安装实例，保存并显示服务器返回的短`KNHREQ3`
#' 申请码。管理员批准后，直接运行[install_knhanes()]即可安装和激活，无需手工
#' 复制授权码。
#'
#' @param version 申请安装的knhanes版本。若为`NULL`，优先读取官方授权服务器的
#'   最新正式版本；网络不可用时依次使用已安装版本和辅助包内置兼容版本。
#' @param quiet 逻辑值。若为`FALSE`，显示申请码和发送说明；若为`TRUE`，只返回
#'   申请码。
#'
#' @details
#' 首次运行会在R用户级knhanesget配置目录生成Ed25519设备签名私钥和Curve25519
#' 设备解密私钥；macOS/Linux将两把私钥文件权限设为`0600`，Windows则使用受限
#' ACL保护，两把私钥均不会离开本机。登记请求只发送安装ID、目标版本、当前用户名、
#' 两把公钥、随机nonce和Ed25519签名，不读取或发送CPU、BIOS、MAC地址或主机名。
#' 服务器返回的`KNHREQ3`申请码不包含私钥，保存在同一配置目录。正常更新或重装R包
#' 不会改变安装ID和设备密钥。
#'
#' 用户名仅用于帮助维护者识别申请设备，不参与授权绑定。申请登记必须连接固定的
#' 官方HTTPS授权服务器。
#'
#' @return 隐式返回以`KNHREQ3.`开头的短申请码字符串。
#' @export
#'
#' @examples
#' \dontrun{
#' request_code <- getToken(quiet = TRUE)
#' }
getToken <- function(version = NULL, quiet = FALSE) {
  kng_scalar_logical(quiet, "quiet")
  if (is.null(version)) {
    version <- tryCatch(
      kng_server_release_metadata("latest")$version,
      error = function(e) NA_character_
    )
    if (is.na(version)) {
      version <- kng_installed_version()
    }
    if (is.na(version)) {
      version <- .kng_compatible_core_version
    }
  }
  version <- kng_normalize_version(version)
  installation_id <- kng_installation_id()
  username <- kng_local_username()
  signing_key <- kng_device_signing_key()
  encryption_key <- kng_device_encryption_key()
  signing_public_key <- kng_base64url_encode(
    sodium::sig_pubkey(signing_key)
  )
  encryption_public_key <- kng_base64url_encode(
    sodium::pubkey(encryption_key)
  )
  nonce <- kng_base64url_encode(sodium::random(18L))
  message <- kng_device_signature_message(
    "knhanes-device-registration-v1",
    kng_server_base_url(),
    installation_id,
    version,
    username,
    signing_public_key,
    encryption_public_key,
    nonce
  )
  registration <- kng_server_request_json(
    "/v1/license-requests",
    method = "POST",
    body = list(
      installation_id = installation_id,
      version = version,
      username = username,
      signing_public_key = signing_public_key,
      encryption_public_key = encryption_public_key,
      nonce = nonce,
      signature = kng_base64url_encode(
        sodium::sig_sign(message, signing_key)
      )
    ),
    expected_status = c(200L, 201L)
  )
  code <- registration$request_code %||% ""
  if (!is.character(code) ||
      length(code) != 1L ||
      !grepl("^KNHREQ3\\.[A-Za-z0-9_-]{32}$", code, perl = TRUE)) {
    stop(
      "The knhanes authorization server returned an invalid request code.",
      call. = FALSE
    )
  }
  kng_write_private_file(code, kng_license_request_path())
  kng_write_private_file(version, kng_license_request_version_path())
  if (!quiet) {
    cat(
      "knhanes \u6388\u6743\u7533\u8bf7\u7801\uff1a\n",
      code,
      "\n\n\u8bf7\u5c06\u5b8c\u6574\u7533\u8bf7\u7801\u548c\u59d3\u540d\u53d1\u9001\u7ed9\u6211\u3002",
      "\n\u90ae\u7bb1\uff1a", .kng_contact, "\n",
      "\u7ba1\u7406\u5458\u6279\u51c6\u540e\uff0c\u76f4\u63a5\u8fd0\u884c ",
      "knhanesget::install_knhanes()\u3002\n",
      sep = ""
    )
  }
  invisible(code)
}

kng_device_signature_message <- function(purpose, ...) {
  kng_scalar_character(purpose, "signature purpose")
  fields <- c(list(purpose), list(...))
  if (length(fields) < 2L ||
      !all(vapply(
        fields,
        function(value) {
          is.character(value) &&
            length(value) == 1L &&
            !is.na(value) &&
            !grepl("[\r\n]", value)
        },
        logical(1)
      ))) {
    stop("Device signature fields are invalid.", call. = FALSE)
  }
  encoded <- lapply(
    unlist(fields, use.names = FALSE),
    function(value) charToRaw(enc2utf8(value))
  )
  Reduce(
    function(left, right) c(left, as.raw(0L), right),
    encoded
  )
}
