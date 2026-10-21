# PCL2 MC客户端下载渠道恢复补丁

给 [Plain Craft Launcher 2](https://afdian.com/a/LTCat) 官方正式版打补丁，
重新开放被关闭的 **Minecraft 下载**功能。

> 当前已知问题：整合包安装均失败报错，待修

> 本仓库**只包含补丁工具**，不包含也不分发修改后的客户端

> 请自行获取官方原版，自行打补丁

> 如果你使用本项目，意味着您应该知悉并为自己的行为负责。项目仅为学习研究，分发本项目文件请遵循**GNU AGPL-3.0**协议。如果您想分发修改后的PCL2软件包，请遵循[《PCL 法律声明》](https://shimo.im/docs/rGrd8pY8xWkt6ryW)

---

## 为什么会有这个补丁

Plain Craft Launcher 2 最新版的MC客户端下载入口关闭，作者在群里说明过原因：

![作者说明](docs/image.png)

功能本身没有任何问题，服务端也没有封锁（`launchermeta.mojang.com` 与
`piston-data.mojang.com` 至今正常响应）（目前旧版本还能正常使用）

---

## 快速开始

```bash
pip install dnfile dncil
python tools/apply.py "Plain Craft Launcher 2.exe"
```

只扫描、不写文件：

```bash
python tools/apply.py "Plain Craft Launcher 2.exe" --scan
```

---

## 补丁做了什么

| 位置 | 恢复的功能 |
|---|---|
| 下载页加载器 | MC 下载列表（原本被替换成「关闭下载」占位） |
| 整合包安装入口 | 拖入 / 选择整合包后能真正开始安装 |
| 整合包安装分派 | 按 CurseForge / Modrinth / HMCL / MMC / MCBBS 等类型走对应流程 |
| 资源详情页 | 整合包页面的「安装」按钮重新出现 |
| 下载页卡片 | 「Minecraft 本体」卡片重新可见 |

补丁只改功能开关，**不碰任何凭据、不联网、不上传文件**。

---

## 注意

- **只支持官方正式版 2.99.0.0 (build 413)**。
  SHA-256 为 `6b6e1260cb5a1d6a303855f1c60cab3d0bc1aebba7e40a964180188b271e7386`。
  其他版本会拒绝执行——不同版本的补丁点字节不同，硬改会写坏文件。
- 本工具不绕过任何付费或授权校验，只恢复被关闭的下载功能。

---

## 许可与致谢

本仓库代码以 **GNU AGPL-3.0** 授权，全文见 [LICENSE](LICENSE)。

**PCL 本身不是开源许可**，而是《PCL 分发有限许可》与
《PCL 存储库合理使用指南》。本工具是第三方独立产物，与龙腾猫跃及 PCL 官方无关，
按该指南的要求：

- 明确声明为第三方产物，不代表官方
- 公开源代码
- 不分发修改后的客户端

PCL 是 [龙腾猫跃](https://afdian.com/a/LTCat) 的作品。如果作者将来重新开放该功能，请直接使用官方版。

---

*本项目仅用于互操作性与个人使用。请支持原作者。*
