# ZuiControl AsoulOpt rules

把 [nakixii/AsoulOpt](https://github.com/nakixii/Magisk_AsoulOpt) 的已审计分类规则转换为 ZuiControl 原生 Schema3。只发布派生规则、静态分析和出处，不发布或执行上游 Magisk ZIP/ELF，也不声明拥有 AsoulOpt。

## 正式下载格式

- `output/rules.conf`：App/Native 使用的 ASCII 规则正文，首行 `schema 3`。
- `output/latest.json`：小于 2048 字节的下载清单，含 revision、SHA-256、大小、来源提交、SM8650/0–7 和必需能力。
- JSON 中 `schema: 2` 是现有 App 的**下载清单协议版本**；`rulesSchema: 3` 才是规则版本。不是两套规则，不生成新的 Schema2 规则包。
- `analysis/*.json`：审计结果，不是下载规则。旧 R1 的 JSON 和报告作为历史证据保留。

GitHub 下载基址：

```text
https://raw.githubusercontent.com/xmy953538104/ZuiControl-Rules/main/output
```

仓库发布不会自动开启设备上的在线源；App 仍由产品工程按此协议接入。Gitee 是 GitHub 源码和同一输出的镜像，当前 App 的网络 allowlist 仍是 GitHub only。

## 保留的规则语义

默认 mode0/rt0；mode0/1/2、rt0/1 是正式能力，opt 不输出。每 profile 保留 `runtime ... -1 -1 preset marker`，不把每 App 的继承值固化为当时全局值。保留 dummy/double 控制标记、分类和竞争顺序；缺必需能力必须拒绝。

当前已审计 Kana ELF SHA-256：`2ac898071119f31ee9080df4eebe2df86dbb67c7e8c4a5b405cbad6000766cf8`，333 个包声明、29 个模板。原始计算路径提取 mode1 的 general/C1/C2=fc/fc/fc；没有用 ZUIopt 的预设值代替上游证据。

输出面向已审计 SM8650 八核适配器。WALT 和 RT 的生效/回退/恢复由设备 Native 能力判定，不把其他平台或未知 ELF 自动视为支持。上游 service.sh 副作用不移植；有限 RT、原值恢复和空代表线程行为保持 ZuiControl 合同。详细差异见 `analysis/runtime-conversion.json`。

上游原包匹配是 ordered strstr，而当前库协议要求 exact 包名。因此按上游顺序解析所有声明包名；`compile_rules` 也支持指定安装包清单来展开已知变体。未来未声明且未展开的变体不会凭空加入云端规则，需更新清单后重新转换；不宣称任意未来包名的无损匹配。

## 自动化

GitHub Actions 在工具修改、手动运行和原有每周日 03:17 UTC（北京时间11:17）检查上游。每次重新核对官方 metadata/release 身份；上游和工具均未变化时不重复下载 ZIP，不增加 revision。工具变化必须重新提取，不能因为上游版本没变而跳过修复。

未知 ELF、指令、掩码、大小、Hash、包语料或规则语法失败，停止发布并保留最后已验证规则。正文和清单只有全部回归通过后才作为一个 Git commit 推送；清单最后落盘，下载必须校验 Hash/大小，不能接受混合版本。

正文未变化时保留原 revision 和出处；正文变化才增加 revision。历史发布保存在 `history/schema3-releases/<revision>/`。旧 `ASOULOPT_UPSTREAM_AUTOMATION_COMPATIBILITY_R1.md`、`reference/zuiopt.json` 是冻结旧后端的比较证据，不代表当前 Schema3 后端缺少 RT。

## 本地检查

Python 3.12+ 标准库、Git、host llvm-objdump，无 Python 依赖。

```sh
python tools/run.py --local-review --objdump /path/to/llvm-objdump
python tools/test_lab.py
python tools/test_runtime_conversion.py
python tools/test_publication.py
git diff --check
```

`--local-review` 仅更新分析，不发布规则。默认 `python tools/run.py` 在已审计输入上生成正式输出；应在已提交的源码上运行。原生解析/序列化子集的来源固定在 `reference/schema3_protocol.json`，没有复制设备 daemon 或另造一种规则格式。

## GitHub / Gitee 同步

GitHub `main` 是编辑与发布源，Gitee 单向跟随。同一正文、清单、revision、Hash 和源码提交应在两端一致。不要分别生成或手工修改 Gitee 的输出；两端有独立提交时先处理差异，不强制覆盖。

Gitee 原生镜像管理入口：
https://gitee.com/xmy953538104/ZuiControl-Rules/mirrors

实际同步资格、最近两端提交和输出 Hash 以本轮交付记录为准；设置存在不等于同步测试通过。
