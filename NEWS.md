# knhanesget 0.1.0.5

* 生产默认发布源改为`https://api.knhanesr.com`，通过短期安装会话下载受保护的
  knhanes发布资产。
* 首次安装可显式传入授权码；后续更新自动复用本地已保存授权，公开函数参数保持
  不变。
* 授权码和短期令牌不进入下载URL或本地持久化文件，发布包仍需同时通过SHA-256与
  Ed25519签名验证。
* 保留`options(knhanesget.release_source = "github")`作为显式GitHub Release
  回退；未设置选项时始终使用生产授权服务器。

# knhanesget 0.1.0.0

* 新增`getToken()`，在安装knhanes前生成兼容`KNHREQ1`申请码。
* 新增`install_knhanes()`，验证SHA-256和Ed25519签名后安装、激活或更新knhanes。
* 新增`knhanes_version()`和`license_status()`查看版本与授权状态。
* 新增`deactivate_device()`删除本地授权并可选重置随机安装ID。
