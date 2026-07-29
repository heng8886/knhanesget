# knhanesget 0.1.0.6

* 普通安装、固定版本安装、更新和版本检查现在只通过官方授权服务器完成，不再包含
  核心包GitHub Release回退路径或相关令牌读取逻辑。
* 官方授权服务器地址固定为`https://api.knhanesr.com`，运行时不接受发布源或
  服务器地址覆盖。
* 所有三个受保护发布资产均强制要求短期安装会话Bearer令牌；缺少令牌时在发出下载
  请求前即失败。
* 跨平台自动检查改为包检查、完整单元测试、公开服务器契约检查和匿名下载拒绝检查，
  不再依赖公开核心包发行仓库。

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
