import base64
import json
from algosdk import account, mnemonic
from algosdk.v2client import algod
from algosdk.future.transaction import PaymentTxn

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

def first_transaction_example(private_key, my_address):
    algod_address = "http://localhost:4001"
    # algod_address = "https://api.testnet.algoexplorer.io"
    algod_token = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    # algod_token = ""
    algod_client = algod.AlgodClient(algod_token, algod_address, headers={ 'User-Agent': 'DoYouLoveMe?' })

    account_info = algod_client.account_info(my_address)
    print("Accoount balance: {} microAlgos".format(account_info.get('amount')) + "/n")

    params = algod_client.suggested_params()
    # comment out the next two (2) lines to use suggested fees
    params.flat_fee = True
    params.fee = 1000
    # receiver = "GD64YIY3TWGDMCNPP553DZPPR6LDUSFQOIJVFDPPXWEG3FVOJCCDBBHU5A"
    receiver = "36JI63UMBEKRVLCYUWL76JIJS5YIUKSQNGXQSK6QZLIJJOWKWH3GPTEFYU"
    note = "Hello World".encode()

    print("params.fee: {}  microAlgos".format(params.flat_fee) + "/n")


    unsigned_txn = PaymentTxn(my_address, params, receiver, 1000000, None, note)

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
    print("Decoded note: {}".format(base64.b64decode(
        confirmed_txn["txn"]["txn"]["note"]).decode()))

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

first_transaction_example("LZbEngFw+W9vz8SScDbzXnqjid+Pc0dEcmaQWKE+lZf85o+crl19EjYMal4Oh00pGvdUZUhCh4JtvQ6tWsdjOw==","7TTI7HFOLV6RENQMNJPA5B2NFENPOVDFJBBIPATNXUHK2WWHMM54XDG5ME")

# Successfully sent transaction with txID: 534QIAPU2CXNB4ZJZPSLA7SOYGOP2EFAGH2Z27VDSVKY6WSP7SUA
# Successfully sent transaction with txID: 6GBB2QG6GJCGG46ONFD3MWS5FYMGHNINGQK6A267K7OR3Q5X3N7Q a mi billetera de algorand