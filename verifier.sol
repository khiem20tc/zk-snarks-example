// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
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
    ) internal view returns (bool) {
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
    ) internal view returns (bool) {
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
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x15b1971fea9f8990d80a4aefbc401d46013668368b7cd9f5e21edb8ac595c887), uint256(0x21b6786106873676487028aa987a2b35909b8c9ac12a22dd75c110be57c911aa));
        vk.beta = Pairing.G2Point([uint256(0x0ffb59529b72657bb0eccd650e564cdc151c5fbd9d4ff998b9023dd9bd31a5a9), uint256(0x0052d8f9fb4eded31d608e309acb38d013ede4c05720b540e3494615b9e05e41)], [uint256(0x13c7d3b935e68fdfe3614ca15ee24cfa91900e599af070e01fbfe420281460ff), uint256(0x0ad05a806de7ad1746a379ed5bebe8350ab4c995e49518481de4b46390d8f932)]);
        vk.gamma = Pairing.G2Point([uint256(0x1275f3cfa2f92699dd694b1fd061b48d9866577ac4bfe56cf72076f25631a5d8), uint256(0x2f17d0702997ac9ff1c2f95614955092184605548f1ca57915a639e9b328f755)], [uint256(0x0cef55f0a520bd1d763f0c8b7f9bac88bdea76c032023056cb0e070dbc74c3c4), uint256(0x2ac5cab6dd1714ac90c5e3999d81453fd5392b3bd6a73526153e07e6226fb1e1)]);
        vk.delta = Pairing.G2Point([uint256(0x2c8fd2eb8a5c46738c954be359bf8f7e8c84708dbd12ddf46e2381b32ba409ef), uint256(0x1632ab9b0a2686bca73a7420587c2cecffcd19eb3a54bf93d7bf475b51af9d88)], [uint256(0x2e80e8d4e7a0cd72910e7ba446e4066d534e7c9f05a2e516f6de73bb68b9a077), uint256(0x21a073a37f5458c17e7c12031d96db8749ce078b673da29e8617555f6db2b547)]);
        vk.gamma_abc = new Pairing.G1Point[](5);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2d069ed3e4edb9aa2f4a74b095608a1bb8195300b877b28b0f33dd2703825162), uint256(0x1aa6f733a7fabf84f187456208214158ed44caacbd379611daa40ef27debef76));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x020985af5279d65f6e6815dde14b45fdf2470887bdce8b75bd5cc6ab0ae41675), uint256(0x1d1c0bcfae136631ee8daceba1bcb8a08d52b8fd709d20293e8cd288a9caad2d));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x03cb93ab4a5fd6ce0081cd5362c372d32b86bd0e5e8d1342db6a0255c8eb9e76), uint256(0x2a924e3980dd5fc35058f2e5e848bcb4b75733cf53b71a4b3443dd46536207c6));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2760bed80c8524312dc7140d74933da20fde3b8a821d284ead23dce354cc2e3b), uint256(0x2b997861430361b36d46b3288e732c34bfa8d975210447fe345e479169a9d897));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2c7b162503db9771b01780808c5366cd39834dd095f431fb2c627fd021bd426f), uint256(0x1d9fb011f8965b35d9e2621e16def82702985b60e3a76e53390d1935768d488d));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[4] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](4);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}