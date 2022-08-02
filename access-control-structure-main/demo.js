const test_cases = [
    
    // AND Gate
    //, {
    //     props: ["Alice", "Carl"],
    //     acs: "Carl AND Alice",
    //     result: true
    // },
    // {
    //     props: ["Alice", "Carl","Tom"],
    //     acs: "Carl AND Alice AND Tom",
    //     result: true
    // },
    // {
    //     props: ["Alice", "Bob", "Carl","Tom"],
    //     acs: "Carl AND (Alice AND (Tom AND Bob))",
    //     result: true
    // },
    // {
    //     props: ["Alice", "Bob", "Carl","Tom","Eve"],
    //     acs: "Carl AND Alice AND (Tom AND Bob) AND Eve",
    //     result: true
    // },
    // {
    //     props: ["Alice", "Bob", "Carl","Tom","Eve","Dav"],
    //     acs: "Carl AND Alice AND (Tom AND Bob) AND Eve AND Dav",
    //     result: true
    // },
    // {
    //     props: ["Alice", "Bob", "Carl","Tom","Eve","Dav","AB"],
    //     acs: "Carl AND Alice AND (Tom AND Bob) AND Eve AND Dav AND AB",
    //     result: true
    // },
    // {
    //     props: ["Alice", "Bob", "Carl","Tom","Eve","Dav","AB","AC"],
    //     acs: "Carl AND Alice AND (Tom AND Bob) AND Eve AND Dav AND AB AND AC",
    //     result: true
    // },
    // {
    //     props: ["Alice", "Bob", "Carl","Tom","Eve","Dav","AB","AC","AD"],
    //     acs: "Carl AND Alice AND (Tom AND Bob) AND Eve AND Dav AND AB AND AC AND AD",
    //     result: true
    // },
    // {
    //     props: ["Alice", "Bob", "Carl","Tom","Eve","Dav","AB","AC","AD","AE"],
    //     acs: "Carl AND Alice AND (Tom AND Bob) AND Eve AND Dav AND AB AND AC AND AD AND AE",
    //     result: true
    // }
    // OR gate
    // ,
    // {
    //     props: ["Alice"],
    //     acs: "Alice OR Carl",
    //     result: true
    // },{
    //     props: ["Alice"],
    //     acs: "Carl OR Alice OR Tom",
    //     result: true
    // },
    // {
    //     props: ["Alice"],
    //     acs: "Carl OR (Alice OR (Tom OR Bob))",
    //     result: true
    // },
    // {
    //     props: ["Alice"],
    //     acs: "Carl OR Alice OR (Tom OR Bob) OR Eve",
    //     result: true
    // },
    // {
    //     props: ["Alice"],
    //     acs: "Carl OR Alice OR (Tom OR Bob) OR Eve OR Dav",
    //     result: true
    // },
    // {
    //     props: ["Alice"],
    //     acs: "Carl OR Alice OR (Tom OR Bob) OR Eve OR Dav OR AB",
    //     result: true
    // },
    // {
    //     props: ["Alice"],
    //     acs: "Carl OR Alice OR (Tom OR Bob) OR Eve OR Dav OR AB OR AC",
    //     result: true
    // },
    // {
    //     props: ["Alice"],
    //     acs: "Carl OR Alice OR (Tom OR Bob) OR Eve OR Dav OR AB OR AC OR AD",
    //     result: true
    // },
    // {
    //     props: ["Alice"],
    //     acs: "Carl OR Alice OR (Tom OR Bob) OR Eve OR Dav OR AB OR AC OR AD OR AE",
    //     result: true
    // },
    {
        props: ["Alice","Carl"],
        acs: "Alice OR Carl",
        result: true
    },{
        props: ["Alice", "Tom"],
        acs: "(Carl OR Alice) AND Tom",
        result: true
    },
    {
        props: ["Alice","Bob"],
        acs: "Carl OR (Alice AND (Tom OR Bob))",
        result: true
    },
    {
        props: ["Alice","Bob","Eve"],
        acs: "(Carl OR Alice) AND (Tom OR Bob) AND Eve",
        result: true
    },
    {
        props: ["Alice","Bob","Eve","Dav"],
        acs: "(Carl OR Alice) AND (Tom OR Bob) AND Eve AND Dav",
        result: true
    },
    {
        props: ["Alice"],
        acs: "Carl OR Alice OR (Tom OR Bob) OR Eve OR Dav OR AB",
        result: true
    },
    {
        props: ["Alice"],
        acs: "Carl OR Alice OR (Tom OR Bob) OR Eve OR Dav OR AB OR AC",
        result: true
    },
    {
        props: ["Alice"],
        acs: "Carl OR Alice OR (Tom OR Bob) OR Eve OR Dav OR AB OR AC OR AD",
        result: true
    },
    {
        props: ["Alice"],
        acs: "Carl OR Alice OR (Tom OR Bob) OR Eve OR Dav OR AB OR AC OR AD OR AE",
        result: true
    },
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