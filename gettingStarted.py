import base64
from io import BufferedIOBase, BufferedRandom, BufferedReader
import json
from algosdk import account, mnemonic
import algosdk
from algosdk.v2client import algod
from algosdk.future.transaction import PaymentTxn
from pinatapy import PinataPy
import base58
import binascii
import requests




# def generate_algorand_keypair():
#     private_key, address = account.generate_account()
#     # print(address)
#     print("My adress: {}".format(address))
#     print("My private key: {}".format(private_key))
#     print("My passphrase: {}".format(mnemonic.from_private_key(private_key)))


# generate_algorand_keypair()    

# este tiene dinero
# My adress: 7TTI7HFOLV6RENQMNJPA5B2NFENPOVDFJBBIPATNXUHK2WWHMM54XDG5ME
# My private key: LZbEngFw+W9vz8SScDbzXnqjid+Pc0dEcmaQWKE+lZf85o+crl19EjYMal4Oh00pGvdUZUhCh4JtvQ6tWsdjOw==
# My passphrase: shield banner sorry abandon very swim kiwi shadow banner supply kangaroo planet eight tiny leave inform material simple creek math dress exile royal above match
# https://testnet.algoexplorer.io/tx/DM6HGMWM7ADOGLCTMROA27LQCSBGRMDWLJHDMYLEOGUCHOU6MCJQ es la tx de 10 algos para testnet

# este no tiene dinero
# My adress: FLRZTG5F3AQLQ3XX42LASLQBJYBVVAETCN2QHIOQROE5IIO56CZTKCDP7U
# My private key: ya6AgY77IlGIHSiZXhAh3vZBi84wKR6x4uYc6bIc38sq45mbpdgguG735pYJLgFOA1qAkxN1A6HQi4nUId3wsw==
# My passphrase: summer actor dolphin rib echo begin unable chimney spring door awesome hospital loop people major circle cat member inflict mushroom grape shrimp galaxy absorb eight

# recibe NFT = YEUJW5EPVUDGXYG67LWCL376GMHYKORJECSB2JAW5WY4ESL3CEHPRSEWX4
creator_mnemonic = "popular sauce pride off fluid you come coffee display list stadium blood scout bargain segment laptop hand employ demise grass sign adult want abstract exhibit"

def first_transaction_example(private_key, my_address, p_url, p_metadataUint8Array):
    # algod_address = "http://localhost:4001"
    # algod_address = "https://api.algoexplorer.io"
    algod_address = "https://api.testnet.algoexplorer.io"
    # algod_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    algod_token = ""
    algod_client = algod.AlgodClient(algod_token, algod_address, headers={ 'User-Agent': 'DoYouLoveMe?' })

    account_info = algod_client.account_info(my_address)
    print("Accoount balance: {} microAlgos".format(account_info.get('amount')) + "/n")

    params = algod_client.suggested_params()
    # comment out the next two (2) lines to use suggested fees
    params.flat_fee = True
    params.fee = 1000
    # receiver = "GD64YIY3TWGDMCNPP553DZPPR6LDUSFQOIJVFDPPXWEG3FVOJCCDBBHU5A"
    receiver = "36JI63UMBEKRVLCYUWL76JIJS5YIUKSQNGXQSK6QZLIJJOWKWH3GPTEFYU"

    arc69_metadata = '{ "standard": "arc69", "description": "arc69 theme video", "external_url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ", "mime_type":"video/mp4", "attributes": [    {"trait_type":"Bass",   "value":"Groovy"      }, {"trait_type":"Vibes",    "value":"Funky"    },   {"trait_type":"Overall",   "value":"Good stuff" }  ]}'

    note_aux = json.loads(arc69_metadata)

    notefield = arc69_metadata.encode()

    print("params.fee: {}  microAlgos".format(params.flat_fee) + "/n")

    
    unsigned_txn = algosdk.future.transaction.AssetConfigTxn(
            sender=my_address,
            sp=params,
            total=1,
            default_frozen=False,
            unit_name="mat"[:7],
            asset_name="certif"[:31],
            manager=my_address,
            reserve=my_address,
            freeze=my_address,
            clawback=my_address,
            url = p_url,
            # metadata_hash = p_metadataUint8Array,
            note=notefield,
            decimals=0)


    # unsigned_txn = PaymentTxn(my_address, params, receiver, 1000000, None, note)

    signed_txn = unsigned_txn.sign(private_key)

    txid = algod_client.send_transaction(signed_txn)
    print("Successfully sent transaction with txID: {}".format(txid))

   

    # wait for confirmation 
    try:
        confirmed_txn = wait_for_confirmation(algod_client, txid, 4)  
    except Exception as err:
        print(err)
        return

    print("Transaction information: {}".format(
        json.dumps(confirmed_txn, indent=4)))

    # aux = json.dumps(confirmed_txn, indent=4)
    print("created asset id:",confirmed_txn["asset-index"])

    # unsigned_optin = algosdk.future.transaction.AssetTransferTxn(
    #         sender=sender_address,
    #         sp=params,
    #         receiver=receiver_address,
    #         amt=int(0),
    #         index=confirmed_txn["asset-index"],
    #         note=None
    #     )


    

    # print("Decoded note: {}".format(base64.b64decode(
    #     confirmed_txn["txn"]["txn"]["note"]).decode()))

# utility for waiting on a transaction confirmation
def wait_for_confirmation(client, transaction_id, timeout):
    """
    Wait until the transaction is confirmed or rejected, or until 'timeout'
    number of rounds have passed.
    Args:
        transaction_id (str): the transaction to wait for
        timeout (int): maximum number of rounds to wait    
    Returns:
        dict: pending transaction information, or throws an error if the transaction
            is not confirmed or rejected in the next timeout rounds
    """
    start_round = client.status()["last-round"] + 1
    current_round = start_round

    while current_round < start_round + timeout:
        try:
            pending_txn = client.pending_transaction_info(transaction_id)
        except Exception:
            return 
        if pending_txn.get("confirmed-round", 0) > 0:
            return pending_txn
        elif pending_txn["pool-error"]:  
            raise Exception(
                'pool error: {}'.format(pending_txn["pool-error"]))
        client.status_after_block(current_round)                   
        current_round += 1
    raise Exception(
        'pending tx not found in timeout rounds, timeout value = : {}'.format(timeout))

# def base58decode(s):
#     b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
#     result = 0
#     for c in s:
#         result = result * 58 + b58.find(c)
#     return result

def pinata():
       print("hola pinata")
       ex = PinataPy("311ae5298e2462a21e7b", "7a38cd9312f97e174dd8477bec9995ea876a29dc3cc426bff6c6cc07b8adc6ba")
    #    print(ex.API_KEY)
       options = {"status": "pinned"}
       ex2 = ex.pin_list(options) 
       print(ex2)

    #    with open('test.pdf', "rb") as output_file:
    #     nftFile = output_file.read()
       

       img_data = requests.get("https://sqsovpcrds-sqsobucket-12jwrpncf5o8h.s3.us-east-1.amazonaws.com/mfj1.jpg").content
       with open('image_name.jpg', 'wb') as handler:
         handler.write(img_data)

       resultFile = ex.pin_file_to_ipfs('image_name.jpg', None)
       print("Algorand NFT::ARC3::IPFS scenario 1: The NFT original digital asset pinned to IPFS via Pinata: ", resultFile)
       print("IpfsHash",resultFile.get('IpfsHash'))
    
    #  ASI es el JSON METADATA
    #  metadata: {
    #     "name": "",
    #     "description": "",
    #     "image": "ipfs://",
    #     "image_integrity": "sha256-",
    #     "image_mimetype": "image/png",
    #     "external_url": "https://github.com/emg110/arc3ipfs",
    #     "animation_url": "",
    #     "animation_url_integrity": "sha256-",
    #     "animation_url_mimetype": "",
    #     "properties": {
    #         "file_url": "",
    #         "file_url_integrity": "",
    #         "file_url_mimetype": "",
    #     }
    # }
 
       aux_metadata = '{"name": "", "description": "", "image": "ipfs://","image_integrity": "sha256-", "image_mimetype": "image/png","external_url": "https://github.com/emg110/arc3ipfs", "animation_url": "","animation_url_integrity": "sha256-","animation_url_mimetype": "", "properties": {"file_url": "",    "file_url_integrity": "", "file_url_mimetype": ""}  }'
       metadata = json.loads(aux_metadata)
       aux_properties = '{"file_url": "loguito", "file_url_integrity": "", "file_url_mimetype": "image/png"}'
       properties = json.loads(aux_properties)
       assetName = "NFT::ARC3::IPFS::1"
       assetDesc = "This is a Scenario1 NFT created with metadata JSON in ARC3 compliance and using IPFS via Pinata API"


 
    #    data = base58decode(resultFile.get('IpfsHash'))
    #    print("b58_1:",data)
       
    #    data2 = base58.b58decode('QmdzE93mUrrGRfYAvMXeKsypyMzCCvVfViowroVV3BaCfx')
       var_ipfshash = resultFile.get('IpfsHash')
    #    file_data = base58.b58decode(resultFile.get('IpfsHash'))
    #    print("b58_2:",file_data)
    # #    base64_bytes = base64.b64encode(data2) anda bien comparado con JS
    #    file_integrity_base64 = base64.b64encode(file_data[2:]).decode('ascii')
    #    print("integrity_base64",file_integrity_base64)
    #    print("")
    #    metadata["properties"] = properties
    #    metadata["properties"]["file_url"] = f'https://ipfs.io/ipfs/{var_ipfshash}'
    #    metadata["properties"]["file_url_integrity"] = f'sha256-{file_integrity_base64}'
    #    metadata["name"] = f'{assetName}@arc3'
    #    metadata["description"] = assetDesc
    #    metadata["image"] = f'ipfs://{var_ipfshash}'
    #    metadata["image_integrity"] = f'sha256-{file_integrity_base64}'
    #    metadata["image_mimetype"] = 'image/png'
    #    print("ipfs:",metadata)
    #    print("")
    #    resultMeta =  ex.pin_json_to_ipfs(metadata, None)
    #    print("resultMeta: ",resultMeta)
    # #    json_integrity_base64 = resultMeta.get('IpfsHash')
    #    resultMetaHash = resultMeta.get('IpfsHash')
    #    json_data = base58.b58decode(resultMeta.get('IpfsHash'))
    # #    json_data2 = base58.b58decode(resultMeta.get('IpfsHash'))
    #    json_integrity_base64 = base64.b64encode(json_data[2:]).decode('ascii')
    #    print("")
    #    print("json_integrity_base64: ",json_integrity_base64)
    #    print("")
    #    sliced_decoded = json_data[2:]
    #    print("cid to byte32: ",binascii.b2a_hex(sliced_decoded).decode("utf-8"))
    #    s = binascii.b2a_hex(sliced_decoded).decode("utf-8")
    #    b = bytearray()
    #    b.extend(map(ord, s))
    #    print(b)
    #    encoded=s.encode('utf-8')
    #    print("encoded:",encoded)
    #    binary_str = binascii.a2b_hex(s)
    #    completed_binary_str = b'\x12 ' + binary_str
    #    print("completed_binary_str ",completed_binary_str)
    #    print("c2: ",base58.b58encode(completed_binary_str).decode("utf-8")) 
 


    #    print("")
 

    #    name = f'{assetName}@arc3'
    #    url = f'ipfs://{resultMetaHash}'
    #    metadata_send = completed_binary_str
    #    integrity = json_integrity_base64
       url = f'ipfs://{var_ipfshash}'
       metadata_send = ""
       first_transaction_example("LZbEngFw+W9vz8SScDbzXnqjid+Pc0dEcmaQWKE+lZf85o+crl19EjYMal4Oh00pGvdUZUhCh4JtvQ6tWsdjOw==","7TTI7HFOLV6RENQMNJPA5B2NFENPOVDFJBBIPATNXUHK2WWHMM54XDG5ME",url,metadata_send)

#        `https://ipfs.io/ipfs/${resultFile.IpfsHash};
#   metadata.properties.file_url_integrity = `sha256-${integrity.base64}`;
#   metadata.name = `${assetName}@arc3`;
#   metadata.description = assetDesc;
#   metadata.image = `ipfs://${resultFile.IpfsHash}`;
#   metadata.image_integrity = `sha256-${integrity.base64}`;;
#   metadata.image_mimetype = `${fileCat}/${fileExt}`;


    #    base64_message = base64_bytes.decode('ascii')
    #    print(" base64_message",base64_message)
    #    print(" base64_bytes",base64_bytes)
    #    metadata["name"]="jose"
    #    print(metadata["name"])




pinata()
# first_transaction_example("LZbEngFw+W9vz8SScDbzXnqjid+Pc0dEcmaQWKE+lZf85o+crl19EjYMal4Oh00pGvdUZUhCh4JtvQ6tWsdjOw==","7TTI7HFOLV6RENQMNJPA5B2NFENPOVDFJBBIPATNXUHK2WWHMM54XDG5ME")

# Successfully sent transaction with txID: 534QIAPU2CXNB4ZJZPSLA7SOYGOP2EFAGH2Z27VDSVKY6WSP7SUA
# Successfully sent transaction with txID: 6GBB2QG6GJCGG46ONFD3MWS5FYMGHNINGQK6A267K7OR3Q5X3N7Q a mi billetera de algorand