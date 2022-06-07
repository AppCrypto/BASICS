const test_cases = [
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
    },
    {
        props: ["Alice", "Bob", "Carl"],
        acs: "Carl AND (Alice AND (Tom OR Bob))",
        result: true
    },
    {
        props: ["Alice", "Bob", "Carl","Tom"],
        acs: "Carl AND (Alice AND (Tom OR Bob))",
        result: true
    }
]

/**
 * 中缀表达式转换成后缀表达式（操作符在后面）
 * @param {String} str 访问控制结构，例如 "Carl AND (Alice OR Bob)"
 * 返回一个数组
 */
function toPostFix(str, props) {
    // 存储结果表达式
    let postFixExp = []
    // 暂存操作符 AND、OR、(、)
    let ops = []

    // 当前单词
    let word = "";

    for (let c of str) {
        // 如果是字母，收集到 word 里
        if (/[a-zA-Z]/.test(c)) {
            word += c;
        }
        // 如果是空格或者括号，就检查 word
        else {
            switch (word) {
                case '': break;

                case 'AND':
                case 'OR':
                    // 检查操作符栈顶元素
                    let top = ops[ops.length - 1];
                    // 如果优先级相同
                    if (top === 'AND' || top === 'OR') {
                        // 将操作符栈顶元素
                        ops.pop()
                        // 转移至后缀表达式
                        postFixExp.push(top)
                    }
                    ops.push(word)
                    break;

                default:
                    // 把属性名添加到后缀表达式
                    postFixExp.push(props.includes(word))
                    break;
            }
            // 清空当前单词
            word = "";

            switch (c) {
                case '(':
                    ops.push(c)
                    break;

                case ')':
                    let top = ops.pop()
                    while (top !== '(') {
                        postFixExp.push(top)
                        top = ops.pop()
                    }
                    break;
            }
        }
    }

    while (ops.length) {
        postFixExp.push(ops.pop())
    }

    // console.log(postFixExp);
    return postFixExp
}

function calcPostFix(postFix) {
    let result = []
    for (const el of postFix) {
        if (typeof el === 'boolean') {
            result.push(el)
        }
        else {
            let el1 = result.pop()
            let el2 = result.pop()
            if (el === 'AND') {
                result.push(el1 && el2)
            }
            if (el === 'OR') {
                result.push(el1 || el2)
            }
        }
    }
    
    // console.log(result);
    return result.pop()
}

module.exports = {
    test_cases,
    toPostFix,
    calcPostFix
};

// const { props, acs } = test_cases[2]
// const pf = toPostFix(acs, props)
// calcPostFix(pf)