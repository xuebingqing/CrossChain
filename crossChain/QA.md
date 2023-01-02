## 合约代码相关
- 库与合约类似，但它的目的是在一个指定的地址，且仅部署一次,然后通过EVM的特性DELEGATECALL来复用代码
- 此外，internal的库函数对所有合约可见
- 如前面合约A在a()方法中调用库C，那引用库C使用的是什么地址呢，C又是如何与A的字节码产生关系的呢。
- 库的关联是发生在字节码层级。当合约A编译后，它会对需要库地址的地方保留一个类似0073__C_____________________________________630dbe671f这样的占位符，注意0dbe671f是a()的签名。如果我们就这样部署A合约，将会失败，因为字节码并不合法。
- 库连接实际上则非常简单，即是替换所有库占位符为部署后的区块链上的库地址。一旦合约已经关联好了对应的库，那么它也可以正式部署了
- 执行时两者都需要部署