import { initialize } from "zokrates-js";

initialize().then((zokratesProvider) => {

    // program is polynomial or boolean (===1/0)
    const source = "def main(public field a, public field b, public field c, private field x) -> field { return a*x*x + b*x - c; }";
  
    // compilation
    const artifacts = zokratesProvider.compile(source);
  
    // computation
    const { witness, output } = zokratesProvider.computeWitness(artifacts, ["2","3","4","5"]);
    console.log("{ witness, output }",{ witness, output })
  
    // run setup
    const keypair = zokratesProvider.setup(artifacts.program);

    console.log("keypair",keypair)
  
    // generate proof
    const proof = zokratesProvider.generateProof(
      artifacts.program,
      witness,
      keypair.pk
    );

    console.log('proof',proof)
  
    // export solidity verifier
    const verifier = zokratesProvider.exportSolidityVerifier(keypair.vk);
    
    console.log('verifier',verifier)
  
    // or verify off-chain
    const isVerified = zokratesProvider.verify(keypair.vk, proof);

    console.log('isVerified',isVerified)
  });