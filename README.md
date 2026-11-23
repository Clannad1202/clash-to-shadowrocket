# Clash to Shadowrocket 自动转换与托管

将 Clash / Mihomo（含 ShellCrash）配置自动转换为 **Shadowrocket（小火箭）** 可直接识别和订阅的托管配置文件与规则集，并通过 **GitHub Actions** 每天自动同步上游规则并更新。

## 解决的核心问题

1. **Mihomo / Clash 规则集不兼容 Shadowrocket**：
   - Clash / Mihomo 配置中的 `rule-providers` 使用了 Mihomo 二进制 `.mrs` 格式（以及 Clash 的 `+.example.com`、裸 IP CIDR、YAML `payload:` 等语法），Shadowrocket 无法直接识别匹配。
   - 本项目脚本会自动拉取上游规则集对应的文本源（支持 `.mrs` 自动映射回退到 `.list` / `.yaml` / `.txt` 与 GitHub 镜像），按 `behavior`（`domain` / `ipcidr` / `classical`）逐条转换为标准的 Shadowrocket 规则语法（`DOMAIN`、`DOMAIN-SUFFIX`、`IP-CIDR`、`IP-CIDR6` 等），并去重清洗无效条目。
2. **策略组与关键字兼容适配**：
   - 完整保留 `config/config.yaml` 中的所有 35 个分流与地区测速策略组（含 `policy-regex-filter` 正则筛选、`url-test` 延迟容差与 `hidden=1` 隐藏组）。
   - 自动将 Clash 专有的 `PASS` 策略映射为 Shadowrocket 支持的 `DIRECT`。
   - 严格保留原有规则中的 `no-resolve` 语义（`privateip`、`telegramip` 保留 `no-resolve`；`cnip`、`netflixip`、`mediaip` 保持解析匹配）。
3. **每日定时自动更新**：
   - GitHub Actions 每天北京时间 **04:30**（`DustinWin/ruleset_geodata` 凌晨 3 点更新后）自动运行，拉取最新规则并提交到 `dist/`，无变更时不产生冗余提交。

---

## 目录结构

```text
.
├── config/
│   ├── config.yaml                # 你的原始 Clash / ShellCrash 配置文件（不含任何节点隐私）
│   └── custom-rules.list          # 独立维护的自定义规则（自动置顶，优先级最高）
├── templates/
│   └── general.ini                # Shadowrocket [General] 基础参数模板（可按需修改）
├── scripts/
│   └── convert.py                 # 核心转换脚本
├── tests/
│   └── test_convert.py            # 单元测试
├── dist/                          # GitHub Actions 自动生成的托管产物
│   ├── shadowrocket-cdn.conf      # 推荐：模块化配置（jsDelivr CDN 加速，国内直连更新更稳）
│   ├── shadowrocket.conf          # 模块化配置（GitHub Raw 地址）
│   ├── shadowrocket-inline.conf   # 单文件内联版（所有规则合并在一个 .conf 中）
│   └── rules/
│       └── *.list                 # 转换后的 19 个 Shadowrocket 规则集文件
└── .github/
    └── workflows/
        └── update.yml             # 每日定时更新与自动提交工作流
```

---

## 快速上手（部署到你的 GitHub）

### 1. 创建公开仓库并推送代码

> ⚠️ 注意：`config/config.yaml` 中**仅包含规则和策略组，不含机场节点与订阅链接**，因此可以安全放在 **Public（公开）** 仓库中，手机端 Shadowrocket 无需配置 Token 即可直接免鉴权自动更新。

```bash
git remote add origin https://github.com/<你的用户名>/<你的仓库名>.git
git push -u origin main
```

### 2. 开启 GitHub Actions 写入权限并首次运行

1. 打开仓库的 **Settings → Actions → General → Workflow permissions**，确保选中 **Read and write permissions**（工作流已声明 `permissions: contents: write`）。
2. 推送后 Actions 会自动触发一次构建，你也可以进入 **Actions → Update Shadowrocket Rules & Config → Run workflow** 手动运行一次。
3. 运行完成后，在 Actions 的 Summary 页面即可看到每个规则集的转换条数统计，仓库的 `dist/` 目录下会生成所有配置文件与 `.list` 规则集。

### 3. 手机端 Shadowrocket 导入与自动更新

将 `<你的用户名>` 和 `<你的仓库名>` 替换为你自己的仓库信息，在 Shadowrocket 的 **配置（Config）→ 右上角 `+`** 中输入以下任一链接下载并设为当前配置：

- **国内网络推荐（模块化 + CDN 加速，体积小、更新快）**：
  ```text
  https://testingcf.jsdelivr.net/gh/<你的用户名>/<你的仓库名>@main/dist/shadowrocket-cdn.conf
  ```
- **GitHub Raw 原链（模块化）**：
  ```text
  https://raw.githubusercontent.com/<你的用户名>/<你的仓库名>/main/dist/shadowrocket.conf
  ```
- **单文件内联版（不依赖外部 `.list` 请求，文件较大）**：
  ```text
  https://testingcf.jsdelivr.net/gh/<你的用户名>/<你的仓库名>@main/dist/shadowrocket-inline.conf
  ```

> 💡 **自动更新说明**：
> - 生成的 `.conf` 顶部已自动写入 `#!MANAGED-CONFIG ... interval=86400 strict=false`。
> - 建议同时在 Shadowrocket 的 **设置 → 订阅 / 配置** 中开启自动更新，并在 iOS **设置 → 通用 → 后台 App 刷新** 中允许 Shadowrocket。
> - 你的机场节点订阅照常在 Shadowrocket 首页添加即可，`[Proxy Group]` 会通过 `policy-regex-filter` 自动把节点归类到对应地区/高级/省流分组。

---

## 本地运行与测试

```bash
# 安装依赖（macOS 在未安装 PyYAML 时也支持内置 Ruby 回退解析）
pip install -r requirements.txt

# 运行单元测试
python3 -m unittest discover -s tests -v

# 手动本地执行转换（将 owner/repo 替换为你的仓库名）
python3 scripts/convert.py \
  --config config/config.yaml \
  --general templates/general.ini \
  --output-dir dist \
  --repo "<你的用户名>/<你的仓库名>" \
  --branch main
```

## 自定义配置

- **增删自定义分流规则**：直接编辑 `config/custom-rules.list`（每行一条 `规则类型,匹配值,策略名[,no-resolve]`，自动插入 `[Rule]` 最顶部，优先级最高）并推送到 `main`，GitHub Actions 会自动重新生成 `dist/`。
- **修改策略组或规则集**：编辑 `config/config.yaml` 并推送到 `main`。
- **修改 Shadowrocket `[General]` 参数**（如开启 `ipv6 = true` 或修改 `dns-server`）：编辑 `templates/general.ini` 并推送即可。
- **自定义托管域名**（例如使用 GitHub Pages 或自建反代）：可在仓库 **Settings → Secrets and variables → Actions → Variables** 中设置 `RAW_BASE_URL` 或 `CDN_BASE_URL`。
