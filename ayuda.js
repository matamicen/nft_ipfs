console.log('Algorand NFT::ARC3::IPFS scenario 1 test connection to Pinata: ', res);
let nftFileName = 'asa_ipfs.png'
const sampleNftFile = fs.createReadStream(`${nftWorkspacePath}/${nftFileName}`);
return scenario1(sampleNftFile, nftFileName, 'NFT::ARC3::IPFS::1', 'This is a Scenario1 NFT created with metadata JSON in ARC3 compliance and using IPFS via Pinata API')
