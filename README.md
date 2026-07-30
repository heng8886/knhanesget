# knhanesget

`knhanesget`是公开的轻量辅助包，用于申请、安装、激活和更新`knhanes`。
它不包含KNHANES数据、knhanes核心分析代码、长期服务器凭据或授权签名私钥。

## 首次安装

```r
install.packages("remotes")
remotes::install_github("heng8886/knhanesget")
```

登记当前电脑并生成短授权申请码：

```r
library(knhanesget)
getToken()
```

将控制台显示的完整`KNHREQ3`申请码和姓名发送给维护者。
邮箱：`henry88866@163.com`。管理员批准后直接运行：

```r
knhanesget::install_knhanes()
```

安装器默认连接`https://api.knhanesr.com`，以本机Ed25519密钥签署一次性挑战，
取得短期安装会话和只能由本机Curve25519私钥解开的激活信封，然后下载受保护的
版本化发布资产。明文授权码只在内存中短暂存在，授权码和短期令牌不会写入下载
URL。随后安装器会依次完成SHA-256校验、Ed25519发布签名验证、读取发布包依赖、
从CRAN自动补齐缺失依赖、R包安装和本地授权激活。Windows和macOS用户通常无需
预先手工安装`dplyr`、`readr`、`survey`等依赖。核心包下载不需要GitHub账号或
PAT。

本机一旦保存`KNHREQ3`申请及完整设备密钥，无参数安装和更新都会强制完成设备
证明；即使已有本地授权文件，也不会降级为旧授权码会话。服务器返回
`device_proof_required`或设备证明失败时，安装器会直接停止，不会静默回退。
首次尚未激活时默认沿用申请时记录的目标版本；激活后的更新会解析最新版本，并以
该精确版本完成新的设备挑战，因此一次有效审批可支持许可证有效期内的后续更新。

为兼容既有授权和故障恢复流程，仍可显式提供完整授权码：

```r
knhanesget::install_knhanes(
  license_code = "KNHLIC3.<payload>.<signature>"
)
```

该在线服务器兼容路径仅接受`KNHLIC3`。旧`KNHLIC1`或`KNHLIC2`若仍被已安装的
knhanes核心包支持，只可在无需服务器下载时用于本地激活。

## 后续更新

已激活用户以后只需运行：

```r
knhanesget::install_knhanes()
```

授权及设备身份保存在R用户配置目录，不会因正常更新或重新安装R包而删除。若年度
授权已经到期，请重新运行`getToken()`并联系维护者续期。

安装固定版本：

```r
knhanesget::install_knhanes(version = "0.1.0.13")
```

## 状态与版本

```r
knhanesget::knhanes_version()
knhanesget::license_status()
```

删除本地授权但保留稳定安装ID：

```r
knhanesget::deactivate_device(confirm = TRUE)
```

同时重置安装ID、申请码和设备密钥（原设备申请及授权将失效）：

```r
knhanesget::deactivate_device(
  confirm = TRUE,
  reset_installation_id = TRUE
)
```

## 安全边界

申请使用随机安装ID，并记录当前操作系统用户名以帮助识别申请设备；不读取CPU、
BIOS、MAC地址或主机名。设备签名私钥和设备解密私钥只保存在本机：
macOS/Linux强制使用目录`0700`和文件`0600`，Windows使用仅限当前账户的ACL。
下载的安装包必须同时通过SHA-256和维护者Ed25519签名验证才会安装。
