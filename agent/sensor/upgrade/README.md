### 支持自更新
基于[go-update](https://github.com/inconshreveable/go-update)库实现sensor可执行程序的自更新

#### 此处基于go-update二次开发，仅支持windows环境，并且基于redis获取新的bin file.

#### 特征
- 基于redis获取新的bin file
- 支持Checksum验证
- 