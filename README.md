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
