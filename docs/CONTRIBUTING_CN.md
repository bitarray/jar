# JAR 贡献指南

> 本指南为 AI 代理和 AI 辅助开发者提供贡献说明。
> 人类贡献者同样欢迎，忽略自动化部分即可。

## 什么是 JAR？

JAR 是 **JAM (Join-Accumulate Machine)** 区块链节点的 Rust 实现。节点名为 **Grey**。实现了 [Gray Paper](https://graypaper.com) 规范。

**Proof of Intelligence**: JAR 代币通过合并 PR 赚取。每个 PR 根据以下维度评分：
- **Difficulty** (难度) — 问题有多难？
- **Novelty** (创新) — 是否为新方法或新想法？
- **Design quality** (设计质量) — 代码是否整洁、符合习惯、测试完善？

`tokens = mass × quality`

## 代码风格规则

1. **纯 Rust** — 核心逻辑不使用异步运行时，不滥用泛型，不使用 trait objects
2. **禁止 `unwrap()`** — 必须正确处理错误
3. **JAM codec** — 使用 `grey-codec` 序列化，**不是 SCALE**
4. **全面测试** — conformance vectors 在 `grey/crates/grey-state/tests/`
5. **SAFETY 注释** — 每个 `unsafe` 块必须有 `// SAFETY:` 注释说明为何安全

## 如何贡献

1. **Fork** `jarchain/jar`
2. **分支**: `git checkout -b feat/your-feature`
3. **修改** — 遵循上述代码风格
4. **测试**: `cargo test -p grey-state`
5. **提交**: 使用常规提交格式 (`feat(grey-rpc): add health endpoint`)
6. **推送** 到你的 fork
7. **开启 PR** 到 `jarchain/jar:master`

## 提交信息格式

```
type(scope): description

feat(grey-rpc): add /health and /ready endpoints
fix(grey-network): handle peer disconnect during sync
docs(grey): add structured logging to README
test(grey-rpc): add integration tests for jam_getStatus
ci: add cargo audit to CI pipeline
```

## 构建

```bash
cd grey
cargo build --release -p grey       # 构建节点
cargo test -p grey-state            # 运行一致性测试
cargo run --release -- --test       # 快速顺序测试
cargo run --release -- --seq-testnet # 确定性测试网
```
