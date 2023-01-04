import cryptography
import secrets
import random
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#########################################################################
def playerEncryptAndShuffle(playerNumber,deck):
    tilekeys = []

    if playerNumber == 1:
        for tile in deck:
            # Generate a random secret key (AES256 needs 32 bytes)
            key = secrets.token_bytes(32)

            nonce = secrets.token_bytes(12)  # GCM mode needs 12 fresh bytes every time

            ciphertextIn = nonce + AESGCM(key).encrypt(nonce, bytes(tile[0], encoding='utf-8'), b"") # Encrypt index
            ciphertextPi = nonce + AESGCM(key).encrypt(nonce, bytes(tile[1], encoding='utf-8'), b"") # Encrypt Pi

            tile[0] = ciphertextIn  # substituir valor no deck
            tile[1] = ciphertextPi

            tilekeys.append([key, ciphertextIn]) # guardar a key para quando for pedido. Como é a msm key usada para index e Pi, só preciso de guardar um deles
    else:
        for tile in deck:
            # Generate a random secret key (AES256 needs 32 bytes)
            key = secrets.token_bytes(32)

            nonce = secrets.token_bytes(12)  # GCM mode needs 12 fresh bytes every time

            ciphertextIn = nonce + AESGCM(key).encrypt(nonce, tile[0], b"") # Encrypt index
            ciphertextPi = nonce + AESGCM(key).encrypt(nonce, tile[1], b"") # Encrypt Pi

            tile[0] = ciphertextIn  # substituir valor no deck
            tile[1] = ciphertextPi

            tilekeys.append([key, ciphertextIn]) # guardar a key para quando for pedido. Como é a msm key usada para index e Pi, só preciso de guardar um deles

    random.shuffle(deck)

    return tilekeys, deck

#########################################################################
def askPlayerTileKeys(playertilekeys, hand):
    playerhandkeys = []

    for handtile in hand:
        for key in playertilekeys:
            if key[1] == handtile[0]:
                playerhandkeys.append(key[0])

    return playerhandkeys

#########################################################################
def decodeHandWithKeys(hand,keys):
    i=0
    for key in keys:
        indexDecoded = AESGCM(key).decrypt(hand[i][0][:12], hand[i][0][12:], b"") # Decrypt (raises InvalidTag if using wrong key or corrupted ciphertext)
        tileDecoded = AESGCM(key).decrypt(hand[i][1][:12], hand[i][1][12:], b"") # Decrypt (raises InvalidTag if using wrong key or corrupted ciphertext)
        hand[i] = [indexDecoded, tileDecoded]
        i += 1

    return hand

#########################################################################
def transformToString(hand):
    for i in range(0, len(hand)):
        hand[i] = [hand[i][0].decode('utf-8'), hand[i][1].decode('utf-8')]

    return hand

#########################################################################
def removePseudonymization(hand,table):
    finalhand = []
    for tile in hand:
        for line in table:
            if tile[1] == line[1]:
                finalhand.append(line[0])
    
    return finalhand
#########################################################################

# deck original do ficheiro 'pieces'
deckoriginal = ["6-6","6-5","6-4","6-3","6-2","6-1","6-0","5-5","5-4","5-3","5-2","5-1","5-0","4-4","4-3","4-2","4-1","4-0","3-3","3-2","3-1","3-0","2-2","2-1","2-0","1-1","1-0","0-0"]

# pseudonomização mal feita só para exemplificar
deckhash = []
pseudonymizationtable = []
for tile in deckoriginal:
    hashed = hash(tile)
    pseudonymizationtable.append([tile,str(hashed)])
    deckhash.append(str(hashed))

# dar shuffle e depois dar um index (igual a meter um index random)
random.shuffle(deckhash)
deck = []

for i in range(0,len(deckhash)):
    deck.append([str(i),  str(deckhash[i])])


#print(pseudonymizationtable)
print('STARTING DECK')
print(deck)
print('\n')

# players dão encrypt e shuffle ao deck
player1tilekeys, deck = playerEncryptAndShuffle(1,deck)
player2tilekeys, deck = playerEncryptAndShuffle(2,deck)
player3tilekeys, deck = playerEncryptAndShuffle(3,deck)

# hand dum player
hand = [deck[0], deck[10], deck[15], deck[20], deck[25]]

# pediu as keys ao player3 enviando os indexs da hand todos encripted
player3handkeys = askPlayerTileKeys(player3tilekeys, hand)
hand = decodeHandWithKeys(hand,player3handkeys)

# pediu as keys ao player2 enviando os indexs da hand todos encripted
player2handkeys = askPlayerTileKeys(player2tilekeys, hand)
hand = decodeHandWithKeys(hand,player2handkeys)

# pediu as keys ao player1 enviando os indexs da hand todos encripted
player1handkeys = askPlayerTileKeys(player1tilekeys, hand)
hand = decodeHandWithKeys(hand,player1handkeys)

transformToString(hand)

print('HAND BEFORE')
print(hand)
print('\n')

# ir a pseudonymization table do server para saber o que significam as hashs
print('PSEUDONYMIZATION TABLE')
print(pseudonymizationtable)
print('\n')

hand = removePseudonymization(hand, pseudonymizationtable)

print('HAND AFTER')
print(hand)
print('\n')