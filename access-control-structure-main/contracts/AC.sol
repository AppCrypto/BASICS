// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

contract AC {

    bytes1 private constant WHITE_SPACE    = bytes1(" ");
    bytes1 private constant LEFT_BRACKETS  = bytes1("(");
    bytes1 private constant RIGHT_BRACKETS = bytes1(")");
    
    bytes private constant AND = bytes("AND");
    bytes private constant OR  = bytes("OR");

    /**
     * @dev 判断访问控制结构真假
     * @notice 
     * @param props  - 属性
     * @param acs    - 访问控制结构
     * @return valid - 是否为真
     */
    function validate(
        string[] memory props,
        string memory acs
    ) public payable returns (bool valid) {
        for (uint256 i = 0; i < props.length; i++) {
            // 记录已有属性
            propsExist[keccak256(abi.encodePacked(props[i]))] = true;
        }

        calcByPostFix(bytes(acs));
        valid = result[0];

        for (uint256 i = 0; i < props.length; i++) {
            // 记录已有属性
            propsExist[keccak256(abi.encodePacked(props[i]))] = false;
        }
    }
    
    // 保存已有的属性
    mapping (bytes32 => bool) propsExist;
    // 暂存操作符 AND、OR、(、)
    bytes[] ops;
    // 存储结果表达式
    bool[] result;

    function calcByPostFix(bytes memory acs) private {

        // 清空两个数组
        delete ops;
        delete result;
    
        // 存储已扫描的单词
        bytes memory word;

        for (uint256 i = 0; i < acs.length; i++) {
            bytes1 c = acs[i];

            // 如果是字母，收集到 word 里
            if ((c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A)) {
                word = bytes.concat(word, c);
            }

            // 如果是空格或者括号，就取出 word
            else {
                // 如果 word 是操作符 AND、OR
                if (bytesEqual(word, AND) || bytesEqual(word, OR)) {
                    // 检查操作符栈顶元素
                    // 如果有操作符，且操作符的栈顶不为左括号
                    if (ops.length > 0 && !bytesEqual(ops[ops.length - 1], "(")) {
                        // 弹出栈顶操作符，执行该操作
                        exec(ops[ops.length - 1]);
                    }
                    // 把新操作符添加到栈顶
                    ops.push(word);
                } 
                
                else if(!bytesEqual(word, "")) {
                    result.push(propsExist[keccak256(abi.encodePacked(word))] == true);
                }

                word = "";

                // 左括号
                if (c == LEFT_BRACKETS) {
                    ops.push(abi.encodePacked(LEFT_BRACKETS));
                }
                
                // 右括号
                if (c == RIGHT_BRACKETS) {
                    // 检查栈顶元素
                    bytes memory top = ops[ops.length - 1];
                    // 如果没有到左括号，就一直执行
                    while (!bytesEqual(top, "(")) {
                        exec(top);
                        top = ops[ops.length - 1];
                    }
                    // 到了左括号跳出循环，把左括号弹出
                    ops.pop();
                }
            }
        }

        while (ops.length > 0) {
            exec(ops[ops.length - 1]);
        }
    }

    function exec(bytes memory op) private {
        // 操作符从栈顶弹出
        ops.pop();
        if(result.length < 2) return;

        // 弹出结果栈的两个元素
        bool t1 = result[result.length - 1];
        bool t2 = result[result.length - 2];
        // 执行操作符，将结果写回栈
        if (bytesEqual(op, AND))
            result[result.length - 2] = (t1 && t2);
        else
            result[result.length - 2] = (t1 || t2);
        
        result.pop();
    }

    function stringEqual(
        string memory a,
        string memory b
    ) private pure returns (bool same) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    function bytesEqual(
        bytes memory a,
        bytes memory b
    ) private pure returns (bool same) {
        return keccak256(a) == keccak256(b);
    }

    function empty() public view {}
}
