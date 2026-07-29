# knhanesget

`knhanesget`是公开的轻量辅助包，用于申请、安装、激活和更新`knhanes`。
它不包含KNHANES数据、knhanes核心分析代码、长期服务器凭据或授权签名私钥。

## 首次安装

```r
install.packages("remotes")
remotes::install_github("heng8886/knhanesget")
```

生成当前电脑的授权申请码：

```r
library(knhanesget)
getToken()
```

将控制台显示的完整`KNHREQ2`申请码和姓名发送给维护者。
邮箱：`henry88866@163.com`。收到维护者签发的`KNHLIC3`授权码后运行：

```r
install_knhanes(
  license_code = "KNHLIC3.<payload>.<signature>"
)
```

安装器默认连接`https://api.knhanesr.com`，使用授权码创建短期安装会话并下载
受保护的版本化发布资产。授权码和短期令牌不会写入下载URL，也不会由辅助包持久化。
随后安装器会依次完成SHA-256校验、Ed25519发布签名验证、读取发布包依赖、从CRAN
自动补齐缺失依赖、R包安装和本地授权激活。Windows和macOS用户通常无需预先手工
安装`dplyr`、`readr`、`survey`等依赖，也不需要GitHub账号或PAT。

## 后续更新

已激活用户以后只需运行：

```r
knhanesget::install_knhanes()
```

授权保存在R用户配置目录，不会因正常更新或重新安装R包而删除。若年度授权已经
到期，需要先向维护者取得新的授权码。

安装固定版本：

```r
knhanesget::install_knhanes(version = "0.1.0.13")
```

## 显式GitHub回退

生产默认源不可用且维护者明确要求回退时，可在当前R会话临时使用旧GitHub
Release源：

```r
options(knhanesget.release_source = "github")
knhanesget::install_knhanes()
options(knhanesget.release_source = NULL)
```

将选项恢复为`NULL`后，后续安装和更新重新使用生产默认授权服务器。无论使用哪种
发布源，安装器都会执行相同的SHA-256和Ed25519发布签名验证。

## 状态与版本

```r
knhanesget::knhanes_version()
knhanesget::license_status()
```

删除本地授权但保留稳定安装ID：

```r
knhanesget::deactivate_device(confirm = TRUE)
```

同时重置安装ID（原授权码将失效）：

```r
knhanesget::deactivate_device(
  confirm = TRUE,
  reset_installation_id = TRUE
)
```

## 安全边界

申请码使用随机安装ID，并记录当前操作系统用户名以帮助识别申请设备；不读取
CPU、BIOS、MAC地址或主机名。下载的安装包
必须同时通过SHA-256和维护者Ed25519签名验证才会安装。
