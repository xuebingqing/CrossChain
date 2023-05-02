## 运行multichain
```json
{
    // 使用 IntelliSense 了解相关属性。 
    // 悬停以查看现有属性的描述。
    // 欲了解更多信息，请访问: https://go.microsoft.com/fwlink/?linkid=830387
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Python: Current File",
            "type": "python",
            "request": "launch",
            "program": "${file}",
            "console": "integratedTerminal",
            "justMyCode": true,
            "args":[
                "-s","~/crossChain/attackExample/multichain/AnyswapV4Router.sol",
                "-c","AnyswapV4Router",
                "--solc", "v0.8.10" ,
                "-g", "20"
            ]
        }
    ]
}

```
- 记得先去切换一下solc的版本