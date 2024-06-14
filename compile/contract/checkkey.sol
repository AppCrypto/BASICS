pragma solidity ^0.8.0;
//pragma experimental ABIEncoderV2;
// import "../contracts/bn128G2.sol";
//import "../contracts/strings.sol";
contract Basics
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

	struct pk_data
	{
		uint256[2]  uPKArr;
		uint256[2][2] APKArr1;
		uint256[2][2] APKArr2;
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

	
	function HashToG1(string memory str) public payable returns (G1Point memory){
		
		return g1mul(P1(), uint256(keccak256(abi.encodePacked(str))));
	}

	function negate(G1Point memory p) public payable returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }

    struct checkkey_Proof
    {
        uint256[2]  EK0Arr; 
        uint256[2][2]  EK1Arr; 
        uint256[2]  EK2Arr;
        uint256[2]  EK0pArr; 
        uint256[2][2] EK1pArr; 
        uint256[2]  EK2pArr; 
        uint256[4]  tmp; 
        string  gid; 
        string  attr;
    }

	pk_data private myPKData;

    checkkey_Proof public checkkeyProof;

	function PKtoSC(
		uint256[2]  memory _uPKArr,
		uint256[2][2] memory _APKArr1,
		uint256[2][2] memory _APKArr2
	) public {
		myPKData = pk_data({
			uPKArr: _uPKArr,
			APKArr1: _APKArr1,
			APKArr2: _APKArr2
		});
	}

    function ProoftoSC(
        uint256[2]  memory _EK0Arr, 
        uint256[2][2]  memory _EK1Arr, 
        uint256[2]  memory _EK2Arr,
        uint256[2]  memory _EK0pArr, 
        uint256[2][2] memory _EK1pArr, 
        uint256[2]  memory _EK2pArr, 
        uint256[4]  memory _tmp, 
        string  memory _gid, 
        string  memory _attr
    ) public { // instantiate struct and assign value
        checkkeyProof = checkkey_Proof({
            EK0Arr: _EK0Arr,
            EK1Arr: _EK1Arr,
            EK2Arr: _EK2Arr,
            EK0pArr: _EK0pArr,
            EK1pArr: _EK1pArr,
            EK2pArr: _EK2pArr,
            tmp: _tmp,
            gid: _gid,
            attr: _attr
        });
    }

	function checkkey1()
	public payable
	    returns (bool)
	{
		G1Point memory uPK=G1Point(myPKData.uPKArr[0], myPKData.uPKArr[1]);
		G1Point memory EK0=G1Point(checkkeyProof.EK0Arr[0], checkkeyProof.EK0Arr[1]);
		G1Point memory EK0p=G1Point(checkkeyProof.EK0pArr[0], checkkeyProof.EK0pArr[1]);

        G1Point memory A1 = g1mul(uPK, checkkeyProof.tmp[1]);
		G1Point memory A2 = g1mul(HashToG1(checkkeyProof.gid), checkkeyProof.tmp[2]);
		G1Point memory A3 = g1mul(HashToG1(checkkeyProof.attr), checkkeyProof.tmp[3]);
		//G1Point memory V0=g1add(g1add(A1,A2),A3);
        require(equals(g1add(EK0p,g1mul(EK0,checkkeyProof.tmp[0])), g1add(g1add(A1,A2),A3)));  //eq1

		//eq2 G2群运算，待补充

		G2Point memory EK1=G2Point(checkkeyProof.EK1Arr[0], checkkeyProof.EK1Arr[1]);

		G2Point memory APK1=G2Point(myPKData.APKArr1[0], myPKData.APKArr1[1]);
		G2Point memory APK2=G2Point(myPKData.APKArr2[0], myPKData.APKArr2[1]);
		
		G1Point memory HGID=HashToG1(checkkeyProof.gid);
		G1Point memory HATTR=HashToG1(checkkeyProof.attr);
		G1Point memory NEG=negate(EK0);

		require(pairingProd4(uPK,APK1,HGID,APK2,HATTR,EK1,NEG, P2()));  //eq3
		return true;
	}

    function checkkey2()
    public payable
	    returns (bool)
	{
        G1Point memory uPK=G1Point(myPKData.uPKArr[0], myPKData.uPKArr[1]);
		G1Point memory EK0=G1Point(checkkeyProof.EK0Arr[0], checkkeyProof.EK0Arr[1]);
		G1Point memory EK0p=G1Point(checkkeyProof.EK0pArr[0], checkkeyProof.EK0pArr[1]);

        G1Point memory A1 = g1mul(uPK, checkkeyProof.tmp[1]);
		G1Point memory A2 = g1mul(HashToG1(checkkeyProof.gid), checkkeyProof.tmp[2]);
		G1Point memory A3 = g1mul(HashToG1(checkkeyProof.attr), checkkeyProof.tmp[3]);
		//G1Point memory V0=g1add(g1add(A1,A2),A3);
        require(equals(g1add(EK0p,g1mul(EK0,checkkeyProof.tmp[0])), g1add(g1add(A1,A2),A3)));  //eq1
		// V1=multiply(G1, tmp[3])
	 	//   assert(V1==add(EK2p, multiply(EK2, tmp[0])))   
	 	//   assert(pairing(G2,EK2)==pairing(EK1,G1))

        G1Point memory EK2=G1Point(checkkeyProof.EK2Arr[0], checkkeyProof.EK2Arr[1]);
        G1Point memory EK2p=G1Point(checkkeyProof.EK2pArr[0], checkkeyProof.EK2pArr[1]);
        require(equals(g1mul(P1(),checkkeyProof.tmp[3]), g1add(EK2p,g1mul(EK2, checkkeyProof.tmp[0]))));  //eq2

		G2Point memory EK1=G2Point(checkkeyProof.EK1Arr[0], checkkeyProof.EK1Arr[1]);
		require(pairingProd2(negate(EK2), P2(), P1(), EK1));  //eq3

		G2Point memory APK1=G2Point(myPKData.APKArr1[0], myPKData.APKArr1[1]);
		G2Point memory APK2=G2Point(myPKData.APKArr2[0], myPKData.APKArr2[1]);
		
		G1Point memory HGID=HashToG1(checkkeyProof.gid);
		G1Point memory HATTR=HashToG1(checkkeyProof.attr);
		G1Point memory NEG=negate(EK0);
		//G1Point memory NEG=EK0;
		//G1Point memory nuPK=negate(uPK);

		require(pairingProd4(uPK,APK1,HGID,APK2,HATTR,EK1,NEG, P2()));  //eq4
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


}