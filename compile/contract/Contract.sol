pragma solidity ^0.8.0;
pragma experimental ABIEncoderV2;
// import "../contracts/bn128G2.sol";
//import "../contracts/strings.sol";
contract Contract
{
	// using bn128G2 for *;
//	using strings for *;
	// p = p(u) = 36u^4 + 36u^3 + 24u^2 + 6u + 1
    uint256 constant FIELD_ORDER = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

    // Number of elements in the field (often called `q`)
    // n = n(u) = 36u^4 + 36u^3 + 18u^2 + 6u + 1
    uint256 constant GEN_ORDER = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    uint256 constant CURVE_B = 3;

    // a = (p+1) / 4
    uint256 constant CURVE_A = 0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52;

	struct G1Point {
		uint X;
		uint Y;
	}

	// Encoding of field elements is: X[0] * z + X[1]
	struct G2Point {
		uint[2] X;
		uint[2] Y;
	}

	// (P+1) / 4
	function A() pure internal returns (uint256) {
		return CURVE_A;
	}

	function P() pure internal returns (uint256) {
		return FIELD_ORDER;
	}

	function N() pure internal returns (uint256) {
		return GEN_ORDER;
	}

	/// return the generator of G1
	function P1() pure internal returns (G1Point memory) {
		return G1Point(1, 2);
	}

	function HashToPoint(uint256 s)
        internal view returns (G1Point memory)
    {
        uint256 beta = 0;
        uint256 y = 0;

        // XXX: Gen Order (n) or Field Order (p) ?
        uint256 x = s % GEN_ORDER;

        while( true ) {
            (beta, y) = FindYforX(x);

            // y^2 == beta
            if( beta == mulmod(y, y, FIELD_ORDER) ) {
                return G1Point(x, y);
            }

            x = addmod(x, 1, FIELD_ORDER);
        }
    }


    /**
    * Given X, find Y
    *
    *   where y = sqrt(x^3 + b)
    *
    * Returns: (x^3 + b), y
    */
    function FindYforX(uint256 x)
        internal view returns (uint256, uint256)
    {
        // beta = (x^3 + b) % p
        uint256 beta = addmod(mulmod(mulmod(x, x, FIELD_ORDER), x, FIELD_ORDER), CURVE_B, FIELD_ORDER);

        // y^2 = x^3 + b
        // this acts like: y = sqrt(beta)
        uint256 y = expMod(beta, CURVE_A, FIELD_ORDER);

        return (beta, y);
    }


    // a - b = c;
    function submod(uint a, uint b) internal pure returns (uint){
        uint a_nn;

        if(a>b) {
            a_nn = a;
        } else {
            a_nn = a+GEN_ORDER;
        }

        return addmod(a_nn - b, 0, GEN_ORDER);
    }


    function expMod(uint256 _base, uint256 _exponent, uint256 _modulus)
        internal view returns (uint256 retval)
    {
        bool success;
        uint256[1] memory output;
        uint[6] memory input;
        input[0] = 0x20;        // baseLen = new(big.Int).SetBytes(getData(input, 0, 32))
        input[1] = 0x20;        // expLen  = new(big.Int).SetBytes(getData(input, 32, 32))
        input[2] = 0x20;        // modLen  = new(big.Int).SetBytes(getData(input, 64, 32))
        input[3] = _base;
        input[4] = _exponent;
        input[5] = _modulus;
        assembly {
            success := staticcall(sub(gas(), 2000), 5, input, 0xc0, output, 0x20)
            // Use "invalid" to make gas estimation work
            //switch success case 0 { invalid }
        }
        require(success);
        return output[0];
    }


	/// return the generator of G2
	function P2() pure internal returns (G2Point memory) {
		return G2Point(
			[11559732032986387107991004021392285783925812861821192530917403151452391805634,
			 10857046999023057135944570762232829481370756359578518086990519993285655852781],
			[4082367875863433681332203403145435568316851327593401208105741076214120093531,
			 8495653923123431417604973247489272438418190587263600148770280649306958101930]
		);
	}

	/// return the negation of p, i.e. p.add(p.negate()) should be zero.
	function g1neg(G1Point memory p) pure internal returns (G1Point memory) {
		// The prime q in the base field F_q for G1
		uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
		if (p.X == 0 && p.Y == 0)
			return G1Point(0, 0);
		return G1Point(p.X, q - (p.Y % q));
	}

	/// return the sum of two points of G1
	function g1add(G1Point memory p1, G1Point memory p2) view internal returns (G1Point memory r) {
		uint[4] memory input;
		input[0] = p1.X;
		input[1] = p1.Y;
		input[2] = p2.X;
		input[3] = p2.Y;
		bool success;
		assembly {
			success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
			// Use "invalid" to make gas estimation work
			//switch success case 0 { invalid }
		}
		require(success);
	}

	/// return the product of a point on G1 and a scalar, i.e.
	/// p == p.mul(1) and p.add(p) == p.mul(2) for all points p.
	function g1mul(G1Point memory p, uint s) view internal returns (G1Point memory r) {
		uint[3] memory input;
		input[0] = p.X;
		input[1] = p.Y;
		input[2] = s;
		bool success;
		assembly {
			success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
			// Use "invalid" to make gas estimation work
			//switch success case 0 { invalid }
		}
		require (success);
	}

	/// return the result of computing the pairing check
	/// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
	/// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
	/// return true.
	function pairing(G1Point[] memory p1, G2Point[] memory p2) view internal returns (bool) {
		require(p1.length == p2.length);
		uint elements = p1.length;
		uint inputSize = elements * 6;
		uint[] memory input = new uint[](inputSize);
		for (uint i = 0; i < elements; i++)
		{
			input[i * 6 + 0] = p1[i].X;
			input[i * 6 + 1] = p1[i].Y;
			input[i * 6 + 2] = p2[i].X[0];
			input[i * 6 + 3] = p2[i].X[1];
			input[i * 6 + 4] = p2[i].Y[0];
			input[i * 6 + 5] = p2[i].Y[1];
		}
		uint[1] memory out;
		bool success;
		assembly {
			success := staticcall(sub(gas()	, 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
			// Use "invalid" to make gas estimation work
			//switch success case 0 { invalid }
		}
		require(success);
		return out[0] != 0;
	}
	/// Convenience method for a pairing check for two pairs.
	function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) view internal returns (bool) {
		G1Point[] memory p1 = new G1Point[](2);
		G2Point[] memory p2 = new G2Point[](2);
		p1[0] = a1;
		p1[1] = b1;
		p2[0] = a2;
		p2[1] = b2;
		return pairing(p1, p2);
	}

	/// Convenience method for a pairing check for three pairs.
	function pairingProd3(
			G1Point memory a1, G2Point memory a2,
			G1Point memory b1, G2Point memory b2,
			G1Point memory c1, G2Point memory c2
	) view internal returns (bool) {
		G1Point[] memory p1 = new G1Point[](3);
		G2Point[] memory p2 = new G2Point[](3);
		p1[0] = a1;
		p1[1] = b1;
		p1[2] = c1;
		p2[0] = a2;
		p2[1] = b2;
		p2[2] = c2;
		return pairing(p1, p2);
	}

	/// Convenience method for a pairing check for four pairs.
	function pairingProd4(
			G1Point memory a1, G2Point memory a2,
			G1Point memory b1, G2Point memory b2,
			G1Point memory c1, G2Point memory c2,
			G1Point memory d1, G2Point memory d2
	) view internal returns (bool) {
		G1Point[] memory p1 = new G1Point[](4);
		G2Point[] memory p2 = new G2Point[](4);
		p1[0] = a1;
		p1[1] = b1;
		p1[2] = c1;
		p1[3] = d1;
		p2[0] = a2;
		p2[1] = b2;
		p2[2] = c2;
		p2[3] = d2;
		return pairing(p1, p2);
	}

	function equals(
			G1Point memory a, G1Point memory b			
	) view internal returns (bool) {		
		return a.X==b.X && a.Y==b.Y;
	}

	function equals2(
			G2Point memory a, G2Point memory b			
	) view internal returns (bool) {		
		return a.X[0]==b.X[0] && a.X[1]==b.X[1] && a.Y[0]==b.Y[0] && a.Y[1]==b.Y[1];
	}

	

    // Costs ~85000 gas, 2x ecmul, + mulmod, addmod, hash etc. overheads
	function CreateProof( uint256 secret, uint256 message )
	    public payable
	    returns (uint256[2] memory out_pubkey, uint256 out_s, uint256 out_e)
	{
		G1Point memory xG = g1mul(P1(), secret % N());
		out_pubkey[0] = xG.X;
		out_pubkey[1] = xG.Y;
		uint256 k = uint256(keccak256(abi.encodePacked(message, secret))) % N();
		G1Point memory kG = g1mul(P1(), k);
		out_e = uint256(keccak256(abi.encodePacked(out_pubkey[0], out_pubkey[1], kG.X, kG.Y, message)));
		out_s = submod(k, mulmod(secret, out_e, N()));
	}

	// Costs ~85000 gas, 2x ecmul, 1x ecadd, + small overheads
	function CalcProof( uint256[2] memory pubkey, uint256 message, uint256 s, uint256 e )
	    public payable
	    returns (uint256)
	{
	    G1Point memory sG = g1mul(P1(), s % N());
	    G1Point memory xG = G1Point(pubkey[0], pubkey[1]);
	    G1Point memory kG = g1add(sG, g1mul(xG, e));
	    return uint256(keccak256(abi.encodePacked(pubkey[0], pubkey[1], kG.X, kG.Y, message)));
	}
	
	function HashToG1(string memory str) public payable returns (G1Point memory){
		
		return g1mul(P1(), uint256(keccak256(abi.encodePacked(str))));
	}

	function checkKey0( uint256[2] memory PKArr, uint256[2] memory EK0Arr, 
		uint256[2] memory EK0pArr, 
 	 	uint256[4] memory tmp, string memory gid, string memory attr)
	    public payable
	    returns (bool)
	{
		G1Point memory PK=G1Point(PKArr[0], PKArr[1]);
		G1Point memory EK0=G1Point(EK0Arr[0], EK0Arr[1]);
		
		G1Point memory EK0p=G1Point(EK0pArr[0], EK0pArr[1]);
		
		G1Point memory A1 = g1mul(PK, tmp[1]);
		G1Point memory A2 = g1mul(HashToG1(gid), tmp[2]);
		G1Point memory A3 = g1mul(HashToG1(attr), tmp[3]);

		G1Point memory V0=g1add(g1add(A1,A2),A3);
		
		G1Point memory V0p = g1add(EK0p, g1mul(EK0, tmp[0]));
		require(equals(V0, V0p));
		
	   
	    return true;
	}

	function negate(G1Point memory p) public payable returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }


	function checkKey1(uint256[2][2] memory EK1Arr, uint256[2][2] memory EK1pArr, uint256[2] memory EK2Arr,  uint256[2] memory EK2pArr, uint256[4] memory tmp)
	    public payable
	    returns (bool)
	{
		G1Point memory EK2=G1Point(EK2Arr[0], EK2Arr[1]);
		G1Point memory EK2p=G1Point(EK2pArr[0], EK2pArr[1]);
		G1Point memory V1=g1mul(P1(), tmp[3]);
		G2Point memory EK1=G2Point(EK1Arr[0], EK1Arr[1]);
		require(equals(V1, g1add(EK2p,g1mul(EK2,tmp[0]))));
		require(pairingProd2(negate(EK2), P2(), P1(), EK1));
		// V1=multiply(G1, tmp[3])
	 //   assert(V1==add(EK2p, multiply(EK2, tmp[0])))   
	 //   assert(pairing(G2,EK2)==pairing(EK1,G1))
	
	    return true;
	}


	bytes[] opstack;
	bytes[] valstack;

    // function push(bytes memory data) public {
    //     stack.push(data);
    // }

    // function pop() public returns (bytes memory data) {
    //     data = stack[stack.length - 1];
    //     // stack.length -= 1;
    //     delete stack[stack.length -1];
    // }


	// function testNode()
	//     public payable
	//     returns (string memory)
	// {
	// 	string memory acp="A or ( B and C )";

	// 	strings.slice memory s = acp.toSlice();                
 //        strings.slice memory delim = " ".toSlice();                            
 //        string[] memory parts = new string[](s.count(delim)+1);                  
 //        for (uint i = 0; i < parts.length; i++) {                              
 //           parts[i] = s.split(delim).toString();                               
 //        }                         

 //        // return parts[parts.length-1];
 //        for (uint i = 0; i < parts.length; i++) {                              
 //        	string memory token = parts[i];
 //        	if(bytes(token)=="")
 //        }
		
	// }

	string private STR = "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd470x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd470x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd470x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd470x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd470x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd470x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd470x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd470x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd470x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd470x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd470x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd470x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd470x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd470x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd470x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd470x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd470x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd470x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd470x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd470x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd470x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";


	function testCall()
        public payable returns (string memory){
        	return STR;
        }


    mapping (string => uint256) public expects;
    mapping (address => mapping(string => uint256)) public pool;
    function Expect(string memory GID, uint256 ownerVal)
	    public payable
	    returns (bool)
	{
		expects[GID]=ownerVal;
	    return true;
	}
	function Deposit(string memory GID)
	    public payable
	    returns (bool)
	{
		pool[msg.sender][GID]=msg.value;
	    return true;
	}

	function Withdraw(string memory GID)
	    public payable
	    returns (bool)
	{
		require(pool[msg.sender][GID]>0, "NO deposits in pool");
		payable(msg.sender).transfer(pool[msg.sender][GID]);
		pool[msg.sender][GID]=0;
	    return true;
	}

	function Reward(address addrU, address addrO, address[] memory addrsAA, string memory GID)
	    public payable
	    returns (bool)
	{
		address payable addru = payable(addrU);
		address payable addro = payable(addrO);
		require(pool[addru][GID]>expects[GID],"NO deposits in pool");
		addro.transfer(expects[GID]);
		pool[addru][GID]=pool[addru][GID]-expects[GID];
		for(uint8 i=0;i<addrsAA.length;i++){
			address payable addraa = payable(addrsAA[i]);
			addraa.transfer(pool[addru][GID]/addrsAA.length);	
		}
		
	    return true;
	}



//contract AC {

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
//}

}