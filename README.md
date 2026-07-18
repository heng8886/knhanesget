# knhanesget

`knhanesget`是公开的轻量辅助包，用于申请、安装、激活和更新`knhanes`。
它不包含KNHANES数据、knhanes核心分析代码、GitHub访问令牌或授权签名私钥。

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

将控制台显示的完整`KNHREQ1`申请码和姓名发送至
`lh1399780@163.com`。收到维护者签发的`KNHLIC2`授权码后运行：

```r
install_knhanes(
  license_code = "KNHLIC2.<payload>.<signature>"
)
```

安装器会依次完成版本解析、下载、SHA-256校验、Ed25519发布签名验证、R包安装和
本地授权激活。用户不需要GitHub账号或PAT。

## 后续更新

已激活用户以后只需运行：

```r
knhanesget::install_knhanes()
```

授权保存在R用户配置目录，不会因正常更新或重新安装R包而删除。若年度授权已经
到期，需要先向维护者取得新的授权码。

安装固定版本：

```r
knhanesget::install_knhanes(version = "0.1.0.3")
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

同时重置安装ID（原授权码将失效）：

```r
knhanesget::deactivate_device(
  confirm = TRUE,
  reset_installation_id = TRUE
)
```

## 安全边界

申请码使用随机安装ID，不读取CPU、BIOS、MAC地址、主机名或用户名。下载的安装包
必须同时通过SHA-256和维护者Ed25519签名验证才会安装。

本过渡方案的发布资产可公开下载，授权主要防止普通复制分享；完整R源码下发到本地
后不能保证对有能力修改源码的使用者不可破解。若未来需要在线撤销、设备数量限制和
审计，应迁移到在线授权服务。
