const AC = artifacts.require("AC");
const { test_cases } = require("../demo");

contract('AC', async () => {

    let gasUsed = []

    for (let testcase of test_cases) {
        const { props, acs, result } = testcase

        it(`[${props}] : ${acs}`, async () => {
            const ac = await AC.deployed();

            /**
             * @param props  - 属性 string[] memory
             * @param acs    - 访问控制结构 string memory
             * @return valid - 是否为真
             */
            console.log("log",props,acs);
            let output = await ac.validate.call(props, acs);
            let gas = await ac.validate.estimateGas(props, acs);

            assert.equal(result, output, "failed")
            gasUsed.push({
                gas,
                props,
                acs
            })
        });
    }

    
    after(`gas used is`, async () => {
        console.table(gasUsed);
    });

});