# JAR - JAM 区块链节点

JAR 是 [JAM (Join-Accumulate Machine)](https://graypaper.com) 协议的 Rust 实现。

## 核心特性

- **100% AI 编写** — 代码全部由 AI 生成
- **Lean 4 形式化验证** — 机器可验证的正确性证明
- **Grey 节点** — 高性能 Rust 实现，比 PolkaVM 快 2.2x

## Proof of Intelligence

无预挖、无团队分配、无投资人轮次。代币仅通过代码贡献获得：

```
提交 PR → 审查排名 → 合并 → 获得 Weight
```

评分维度：Difficulty + Novelty + Design Quality（3x权重）

## Coinless 设计

基础层无原生代币，交易免费。服务层可发行自己的代币经济。

## 快速开始

```bash
# 构建
cargo build --release -p grey

# 测试
cargo test -p grey-state

# 运行
cargo run --release -- --test
```

## 文档

- [贡献指南](CONTRIBUTING_CN.md)
- [GENESIS.md](../GENESIS.md) - Proof of Intelligence 机制
- [Gray Paper](https://graypaper.com) - 协议规范

## 许可证

GPL-3.0
