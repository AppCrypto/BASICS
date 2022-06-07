# access-control-structure

访问控制结构

## 运行

运行指定的测试文件 

```shell
$ pnpm install
$ pnpm truffle test .\test\funcTest.js
```

如果提示没有安装 pnpm，就全局安装一下

```shell
$ npm install -g pnpm
```

## 测试用例

见 `./demo.js`，包含以下几组

```javascript
[
    {
        props: ["Alice", "Bob"],
        acs: "Alice AND Bob",
        result: true
    },
    {
        props: ["Alice", "Bob"],
        acs: "Alice OR Bob",
        result: true
    },
    {
        props: ["Alice", "Bob"],
        acs: "Carl AND (Alice OR Bob)",
        result: false
    },
    {
        props: ["Alice", "Bob"],
        acs: "Carl OR (Alice AND (Tom OR Bob))",
        result: true
    }
]
```

## 结果

```txt
┌─────────┬────────┬────────────────────┬────────────────────────────────────┐
│ (index) │  gas   │       props        │                acs                 │
├─────────┼────────┼────────────────────┼────────────────────────────────────┤
│    0    │ 224465 │ [ 'Alice', 'Bob' ] │          'Alice AND Bob'           │
│    1    │ 223828 │ [ 'Alice', 'Bob' ] │           'Alice OR Bob'           │
│    2    │ 343055 │ [ 'Alice', 'Bob' ] │     'Carl AND (Alice OR Bob)'      │
│    3    │ 417444 │ [ 'Alice', 'Bob' ] │ 'Carl OR (Alice AND (Tom OR Bob))' │
└─────────┴────────┴────────────────────┴────────────────────────────────────┘
```