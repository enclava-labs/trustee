# csv-rs

csv-rs crate库提供了对HYGON CSV API接口的rust实现。

CSV API根据其被调用的方式分为：
1. 在主机侧调用的Management API
2. 在虚拟机侧调用的Guest API。
3. DCU 相关的调用DCU API

其中Management API根据其功能又分为：
1. 管理CSV Platform的API
2. 启动CSV KVM虚拟机的API

该crate中会陆续实现上述API的high level接口，提供给
上层软件调用。

## Management API
### Platform Management
请参考[Platform API 相关文档](https://github.com/openanolis/csv-rs/blob/af78aaaf60a9747eac6d45c0c80a3664f1494ef8/docs/platform/README.md).
### Launch Management
请参考[Launch API 相关文档](https://github.com/openanolis/csv-rs/blob/af78aaaf60a9747eac6d45c0c80a3664f1494ef8/docs/launch/README.md).
## Guest API
请参考[Guest API 相关文档](https://github.com/openanolis/csv-rs/blob/af78aaaf60a9747eac6d45c0c80a3664f1494ef8/docs/guest/README.md).

## DCU API
请参考[DCU API 相关文档](https://github.com/openanolis/csv-rs/blob/7f54d3f925972b9d3c4a6e01ce5a1fe974203dfb/docs/dcu/README.md).

License: Apache-2.0