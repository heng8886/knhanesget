# knhanesget 0.1.0.7

* `getToken()`现在向固定官方HTTPS服务器登记本机生成的Ed25519签名公钥和
  Curve25519加密公钥，并保存服务器返回的短`KNHREQ3`申请码。
* 管理员批准申请后，用户只需运行`install_knhanes()`；安装器通过带签名的
  一次性挑战取得短期下载会话和设备加密激活信封，不再要求用户复制完整授权码。
* 设备注册、挑战和安装会话签名均采用固定域名绑定的NUL分隔canonical消息；
  版本、安装ID、双公钥指纹、nonce和一次性challenge均纳入签名。
* Ed25519和Curve25519私钥保存在`knhanesget`用户配置目录。macOS/Linux强制
  目录`0700`、文件`0600`；Windows使用`icacls`关闭继承、限制当前账户并回读
  验证ACL，并移除Everyone、Users和Authenticated Users广泛主体。符号链接、
  损坏密钥或权限收紧失败均会中止；Windows CI对真实临时文件执行ACL写入和SID
  回读集成检查。
* 已安装目标版本但尚未激活时，只领取并解密激活信封，不重复下载或安装R包。
* 保留`install_knhanes(license_code = ...)`及既有本地授权更新流程，公开函数
  参数保持兼容。
* 已登记`KNHREQ3`及完整设备密钥的用户，无参数安装或更新时始终走设备挑战，
  即使本地已有授权也不会降级到旧授权码会话；`device_proof_required`等设备证明
  错误会直接中止。
* 首次尚未激活且请求`latest`时仍使用申请时保存的版本，避免审批期间新版本发布
  造成漂移；已有本地授权的登记设备更新时解析最新Release，并以目标精确版本完成
  challenge/session，不再永久锁定首次申请版本。

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
