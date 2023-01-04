import base64
import hashlib
import json
import pickle
import socket
import sys
import logging
import Colors
import string
from deck_utils import Player,Piece
import random
from hashlib import sha256
import security_utils
import cc_utils
from security_utils import DH

import ast
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def interrupt(msg):
    return
    input(msg)

class client():
    def __init__(self, host, port, cheat, name):
        self.name = name
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.connect((host, port))
        first_msg = {"action": "hello"}
        self.sock.send(pickle.dumps(first_msg))
        self.player = None
        self.receiveData()
        self.all_tilekeys = []
        self.bitcommitment_key = ''
        self.bitcommitment_msg = ''
        self.bitcommitment_res = ''
        self.all_bitcommitments = []
        self.initialdeck = []
        self.cheat = cheat
        self.indexes_to_deanon_remaining = []
        self.indexes_to_deanon_save = []
        self.privkeylist = []
        self.forcevalidate = 0


    def receiveData(self):
        while True:
            data = b''
            while True:
                packet = self.sock.recv(8192)
                data += packet
                if len(packet)<8192:
                    break

            while len(data)>0:
                if data:
                    json_data = pickle.loads(data)

                    data = data[len(pickle.dumps(json_data)):]
                    if len(data)>0:
                        pass
                    self.handle_data(json_data)

    def getSessionKey(self,name):
        key = ''
        if name == "server":
            key = self.player.keys["dh_server"].full_key
        else:
            for opponent in self.player.opponents:
                if name == opponent['name']:
                    key = opponent["dh"].full_key
        return key

    def confirmHmac(self, msg, sentby, hmac):
        key = self.getSessionKey(sentby)
        calcHMAC = security_utils.hmac_sha512(msg,key)
        if calcHMAC == hmac:
            print(Colors.BYellow + "Verified HMAC of message sent by "+Colors.Color_Off + sentby)
            #input("Verified")
            return True
        return False


    def handle_data(self, data):
        #data = pickle.loads(data)
        global action
        action = data["action"]
        print("\n" + action)
        if action != "login" and action !="new_player" and action !="server_dh_negotiations" and action !="wait" and action !="":
            sentby = data["sentby"]
            hmac = data["hmac"]
            data.pop("sentby")
            data.pop("hmac")
            if not self.confirmHmac(data, sentby, hmac):
                print(Colors.BRed + "Invalid HMAC, integrity compromised. Aborting game." + Colors.Color_Off)
                exit(-1)



        if action == "login":
            #nickname = input("Insert Name")#
            if self.name is None:
                nickname = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))  # input(data["msg"])
            else:
                nickname = self.name
            print("Your name is " + Colors.BBlue + nickname + Colors.Color_Off)
            self.player = Player(nickname, self.sock)
            print("Generating ASYM KEYS")
            pub, priv = security_utils.createAsymKeys()
            #DH SERVER
            dh = DH()
            server_pub = security_utils.load_server_pub_key()
            if not security_utils.verify_cert_pubkey(data["server_cert"],server_pub):
                print(Colors.BRed+"Certificate received from server not recognized!"+Colors.Color_Off)
                exit(-1)
            print(Colors.BGreen+"Server Public Key Validated."+Colors.Color_Off)

            self.player.keys.update({"priv_key": priv, "pub_key": pub, "server_pub_key":server_pub, "dh_server":dh})
            to_send = {"msg": nickname, "pub_key": base64.b64encode(pub).decode('ascii')}

            to_send = security_utils.toBytes(json.dumps(to_send))
            to_send = security_utils.cipherAsymKey(server_pub,to_send)
            msg={"action": "req_login","msg":to_send }

            print('\n'+Colors.BCyan+"Sending server my public key and nickname (encrypted with his public key): "+Colors.Color_Off, msg)
            print('\n'+Colors.BCyan+"My currently saved keys: "+Colors.Color_Off, self.player.keys)

            self.sock.send(pickle.dumps(msg))
            return

        elif action == "server_dh_negotiations":
            if data["action1"] == "you_host":
                self.player.host = True
                print(data["msg"])
            pub_key = security_utils.decipherAsymKey(self.player.keys["priv_key"], data["dh_key"]).encode('utf-8')
            print('\n'+Colors.BCyan+"Public key from server for diffie-hellman (after decrypting with previous one): "+Colors.Color_Off, pub_key)

            dh = self.player.keys["dh_server"]

            dh.loadPeerPubKey(pub_key,pem=False)
            dh.generate_partial_key()
            dh.generate_full_key()
            print( " \nServer session key: " + Colors.BYellow + "{}".format(
                   dh.full_key) + Colors.Color_Off)
            cyphred = security_utils.cipherAsymKey(self.player.keys["server_pub_key"], dh.pulicKeyToPEM())
            msg = {"action": "reply_dh_negotiations","dh_key": cyphred}
            self.sock.send(pickle.dumps(msg))

        elif action == "new_player":
            print(data["msg"])
            print("There are " + str(data["nplayers"]) + "\\" + str(data["game_players"]))

        elif action == "receive_players_information":
            players_info = list(data["players"])
            for player in data["players"]:
                if player["name"] != self.player.name:
                    players_info.append(players_info.pop(0))
                else:
                    players_info.pop(0)
                    self.player.opponents = players_info
                    break
            for player in self.player.opponents:
                # print("player " + Colors.BBlue + "{}".format(player["name"]) + Colors.Color_Off +
                #       " \nkeys: " + Colors.BYellow + "{}".format(
                #     player["pub_key"]) + Colors.Color_Off)
                dh = DH()
                player.update({"dh": dh})

                #public key decoded into string
                to_send = {"action": "dh_negotiations", "msg": dh.pulicKeyToPEM().decode('utf-8')}
                #convert json to str
                to_send = json.dumps(to_send)
                cyphred = security_utils.cipherAsymKey(player["pub_key"], to_send)
                msg = {"action": "send_to", "player_name": player["name"], "sent_by": self.player.name,
                       "msg": cyphred}
                self.sock.send(pickle.dumps(msg))

        elif action == "rcv_from_player":
            print("Message received from player " + Colors.BBlue + "{}".format(
                data["sent_by"]) + Colors.Color_Off + "")
            for opponent in self.player.opponents:
                if opponent["name"] == data["sent_by"]:
                    if "dh" in opponent:
                        dh = opponent["dh"]
                        if dh.peer_pub_key== None:
                            request = json.loads(security_utils.decipherAsymKey(self.player.keys["priv_key"], data["msg"]))
                            if request["action"] == "dh_negotiations":
                                pub_key = request["msg"].encode('utf-8')
                                #print(pub_key)
                                dh.loadPeerPubKey(pub_key, pem=False)
                                dh.generate_partial_key()
                                dh.generate_full_key()
                                #print(dh.full_key)
                                # public key decoded into string
                            if all([opponent["dh"].full_key != None for opponent in self.player.opponents]):
                                print("\nplayer " + Colors.BBlue + "{}\n".format(self.player.name) + Colors.Color_Off )
                                for opponent in self.player.opponents:
                                    print("\nplayer " + Colors.BBlue + "{}".format(opponent["name"]) + Colors.Color_Off +
                                          " session key: " + Colors.BYellow + "{}".format(
                                        opponent["dh"].full_key) + Colors.Color_Off)
                                print(Colors.BBlue + "\nServer " + Colors.Color_Off +
                                      " session key:  " + Colors.BYellow + "{}".format(
                                    self.player.keys["dh_server"].full_key) + Colors.Color_Off)

                                msg = {"action": "dh_sessions_finished"}
                                self.sock.send(pickle.dumps(msg))
                                interrupt("Check DH")

                        elif dh.full_key != None:
                            data2 = security_utils.decipherSymKey(dh.full_key,data["msg"])
                            data2 = json.loads(data2)

                            sentby = data2["sentby"]
                            hmac = data2["hmac"]
                            hmac = base64.b64decode(hmac.encode('ascii'))
                            data2.pop("sentby")
                            data2.pop("hmac")

                            if not self.confirmHmac(data2, sentby, hmac):
                                print(
                                    Colors.BRed + "Invalid HMAC, integrity compromised. Aborting game." + Colors.Color_Off)
                                exit(-1)

                            if data2["action"] == "get_initial_pieces":
                                bdeck = []
                                for tile in data2["deck"]:
                                    bdeck.append([tile[0],base64.b64decode(tile[1].encode('ascii'))])
                                data2["deck"]= bdeck
                                data = data2
                                action = data["action"]
                            elif data2["action"] == "deanonymize":
                                data = data2
                                action = data["action"]

                    else:
                        print("\n\n\nSHIIIIIIT \n\n\n")
                    break

        elif action == "rcv_from_player_unencrypted":

            print("Message un_encrypted received from player " + Colors.BBlue + "{}".format(
                 data["sent_by"]) + Colors.Color_Off )
            data2 = data["msg"]

            sentby = data2["sentby"]
            hmac = data2["hmac"]
            data2.pop("sentby")
            data2.pop("hmac")
            if not self.confirmHmac(data2, sentby, hmac):
                print(Colors.BRed + "Invalid HMAC, integrity compromised. Aborting game." + Colors.Color_Off)
                exit(-1)

            if data2["action"] == "encrypt_deck":
                if self.player.firstencription:
                    action = data2["action"]
                    data = data2
                    print(action)
                else:
                    msg = {"action": "encryption_done", "deck": data2["deck"]}
                    hmac = security_utils.hmac_sha512(msg, self.getSessionKey("server"))
                    msg.update({"sentby": self.player.name, "hmac": hmac})
                    print(Colors.BGreen+"Deck encrypted by all clients sent to server."+Colors.Color_Off)
                    self.sock.send(pickle.dumps(msg))


        elif action == "waiting_for_host":
            assert all([opponent["dh"].full_key != None for opponent in self.player.opponents])
            self.player.nplayers = data["nplayers"]
            self.player.npieces = data["npieces"]
            self.player.pieces_per_player = data["pieces_per_player"]
            if self.player.host:
                #input(Colors.BGreen + "PRESS ENTER TO START THE GAME" + Colors.Color_Off)
                msg = {"action": "start_game"}
                self.sock.send(pickle.dumps(msg))
                print("Sent ", msg)
            else:
                print(data["msg"])

        elif action == "rcv_from_server":
            print("Encrypted message received from " + Colors.BBlue + "{}".format(
                 "Server") + Colors.Color_Off )
            dh = self.player.keys["dh_server"]
            data2 = security_utils.decipherSymKey(dh.full_key, data["msg"])
            data = json.loads(data2)
            action = data["action"]

        if action == "encrypt_deck":
            self.player.firstencription = False
            interrupt("encrypt_deck PRESS ENTER\n")
            self.player.deck = data["deck"]

            checkColusion = True

            for i,tile in enumerate(self.player.deck):
                while(checkColusion):
                    checkColusion = False
                    # Generate a random secret key (AES256 needs 32 bytes)
                    key = secrets.token_bytes(32)
                    nonce = secrets.token_bytes(12)  # GCM mode needs 12 fresh bytes every time
                    ciphertext = nonce + AESGCM(key).encrypt(nonce, tile, b"") # Encrypt

                    #check collusion
                    for kt in self.player.tilekeys:
                        if kt[1] == ciphertext:
                            print(Colors.BRed+"Houve colisão e a chave foi receita."+Colors.Color_Off)
                            checkColusion=True
                    if checkColusion == False:
                        self.player.deck[i] = ciphertext
                        self.player.tilekeys.append([key, ciphertext]) # guardar a key para quando for pedido. Como é a msm key usada para index e Pi, só preciso de guardar um deles
                checkColusion = True

            random.shuffle(self.player.deck)
            print(Colors.BYellow+"Deck após cifração: "+Colors.Color_Off,self.player.deck)
            print()
            print(Colors.BYellow+"Tabela (key,ciphertext) do cliente: "+Colors.Color_Off,self.player.tilekeys)
            print()
            to_send = {"action": "encrypt_deck", "deck": self.player.deck}
            hmac = security_utils.hmac_sha512(to_send, self.getSessionKey(self.player.opponents[0]["name"]))
            to_send.update({"sentby": self.player.name, "hmac": hmac})

            msg = {"action": "send_to_unencrypted", "player_name": self.player.opponents[0]["name"],
                   "sent_by": self.player.name, "msg": to_send}
            hmac = security_utils.hmac_sha512(msg, self.getSessionKey("server"))
            msg.update({"sentby": self.player.name, "hmac": hmac})


            self.sock.send(pickle.dumps(msg))

        elif action == "get_bitcommitment":
            msg = ''
            for tile in self.player.hand:
                msg += tile[0] +','
            self.bitcommitment_msg = msg[:(len(msg)-1)]
            self.bitcommitment_key = "{0:0{1}x}".format(random.getrandbits(256), 64)
            encoded_value = (self.bitcommitment_msg+self.bitcommitment_key).encode()
            self.bitcommitment_res = sha256(encoded_value).hexdigest()
            msg = {"action": "rcv_bitcommitment", "bitcommitment": self.bitcommitment_res}
            hmac = security_utils.hmac_sha512(msg, self.getSessionKey("server"))
            msg.update({"sentby": self.player.name, "hmac": hmac})
            self.sock.send(pickle.dumps(msg))

        elif action == "rcv_info":
            self.all_bitcommitments = data['all_bitcommitments']
            self.initialdeck = data['initialdeck']

            print(Colors.BGreen+'\nALL BITCOMMITMENTS:'+Colors.Color_Off)
            for b in self.all_bitcommitments:
                print(Colors.BCyan+b[0]+Colors.Color_Off + ": " + b[1])
            interrupt(Colors.BBlue+'Press Enter to continue...'+Colors.Color_Off)
            msg = {"action": "start_decrypt"}
            hmac = security_utils.hmac_sha512(msg, self.getSessionKey("server"))
            msg.update({"sentby": self.player.name, "hmac": hmac})
            self.sock.send(pickle.dumps(msg))

        elif action == "get_tilekeys":
            self.player.deck = data["deck"]
            self.all_tilekeys = data["all_tilekeys"]

            p = len(self.player.opponents)+1

            tiles_in_play = [item for item in self.initialdeck if item not in self.player.deck]
            for tilekeys in self.all_tilekeys:
                if tilekeys != None:
                    i = 0
                    for tile in tiles_in_play:
                        for key in tilekeys:
                            if key[1] == tile[1]:
                                tileDecoded = AESGCM(key[0]).decrypt(key[1][:12], key[1][12:],b"")  # Decrypt (raises InvalidTag if using wrong key or corrupted ciphertext)
                                tiles_in_play[i] = [tile[0], tileDecoded]
                                i += 1
                                print(Colors.BBlue + "(in play) Tile of index " + str(tile[0]) + " decrypted with keys of player "+str(p)+"."+Colors.Color_Off)
                                break
                p -= 1

            tilekeys_tosend = []

            for tile in tiles_in_play:
                for key in self.player.tilekeys:
                    if tile[1] == key[1]:
                        tilekeys_tosend.append(key)
                        break

            print(Colors.BYellow+"Chaves para decifrar tiles em jogo enviadas..."+Colors.Color_Off)

            for index_tilekeys in range(0,len(self.all_tilekeys)):
                if self.all_tilekeys[index_tilekeys] == None:
                    self.all_tilekeys[index_tilekeys] = tilekeys_tosend
                    break

            msg = {"action": "start_decrypt", "all_tilekeys":self.all_tilekeys}
            hmac = security_utils.hmac_sha512(msg, self.getSessionKey("server"))
            msg.update({"sentby": self.player.name, "hmac": hmac})
            self.sock.send(pickle.dumps(msg))

        elif action == "decrypt_hand":

            interrupt(Colors.BBlue + "Start decrypting... (Press Enter)" + Colors.Color_Off)
            self.all_tilekeys = data["all_tilekeys"]
            print(Colors.BCyan+"I have all keys needed to decrypt my hand..."+Colors.Color_Off)

            for player,tilekeys in enumerate(self.all_tilekeys):
                for i,tile in enumerate(self.player.hand):
                    for key in tilekeys:
                        if key[1] == tile[1]:
                            tileDecoded = AESGCM(key[0]).decrypt(key[1][:12], key[1][12:], b"") # Decrypt (raises InvalidTag if using wrong key or corrupted ciphertext)
                            self.player.hand[i] = [tile[0],tileDecoded]
                            print(Colors.BIRed + "(Hand) Tile of index "+str(tile[0])+" decrypted "+str(player+1)+" times."+ Colors.Color_Off)
                            break

            #decode de byte
            indexes_to_deanon = []
            for i in range(0,len(self.player.hand)):
                self.player.hand[i] = self.player.hand[i][1].decode('utf-8')
                self.player.hand[i] = ast.literal_eval(self.player.hand[i])
                indexes_to_deanon.append(int(self.player.hand[i][0]))

            print(Colors.BCyan+"Tile indexes to deanonymize: "+Colors.Color_Off,indexes_to_deanon)

            self.indexes_to_deanon_save = indexes_to_deanon.copy()
            self.indexes_to_deanon_remaining = indexes_to_deanon.copy()

            privkeylist = [None] * 28
            for index in self.indexes_to_deanon_save:
                pub_key, priv_key = security_utils.createAsymKeys()
                privkeylist[index] = [pub_key, priv_key]

            self.privkeylist = privkeylist
            print(Colors.BCyan+"Created "+str(len(indexes_to_deanon))+ " public/private key pairs.")

            msg = {"action": "deanonymize"}
            hmac = security_utils.hmac_sha512(msg, self.getSessionKey("server"))
            msg.update({"sentby": self.player.name, "hmac": hmac})
            self.sock.send(pickle.dumps(msg))

        elif action == "deanonymize":
            interrupt("INIt deanonymize")
            deanon_array = data['de_anon']
            pass_play = random.randint(0, 100)
            if pass_play > 94:
                if len(self.indexes_to_deanon_remaining) == 0:
                    if (len(deanon_array)-deanon_array.count(None))==((len(self.player.opponents)+1) * self.player.pieces_per_player):
                        msg = {"action": "done_deanonymize", "de_anon": deanon_array}
                        print(Colors.BGreen + "Told server it is done." + Colors.Color_Off)
                        return self.sock.send(pickle.dumps(msg))
                else:
                    index = self.indexes_to_deanon_remaining.pop()
                    deanon_array[index] = base64.b64encode(self.privkeylist[index][0]).decode('ascii')
                    print(Colors.BGreen+"Added public key."+Colors.Color_Off)

            else:
                print(Colors.BGreen + "Did nothing." + Colors.Color_Off)

            to_send = {"action": "deanonymize","de_anon": deanon_array}
            next_player = random.choice(self.player.opponents)
            dh = next_player["dh"]
            hmac = security_utils.hmac_sha512(to_send, self.getSessionKey(next_player['name']))
            hmac = base64.b64encode(hmac).decode('ascii')

            to_send.update({"sentby": self.player.name, "hmac": hmac})
            to_send = security_utils.toBytes(json.dumps(to_send))
            cyphred = security_utils.cipherSymKey(dh.full_key, to_send)

            msg = {"action": "send_to", "player_name": next_player["name"],
                   "sent_by": self.player.name, "msg": cyphred}
            hmac = security_utils.hmac_sha512(msg, self.getSessionKey("server"))
            msg.update({"sentby": self.player.name, "hmac": hmac})
            self.sock.send(pickle.dumps(msg))

        elif action == "rcv_deanonymize":
            deanon_array = data['de_anon']

            # criar objetos piece através dos id (ex: id '35' vai originar a Piece(3,5))
            i = 0
            for index in self.indexes_to_deanon_save:
                info = security_utils.decipherAsymKey(self.privkeylist[index][1],deanon_array[index])
                info = ast.literal_eval(info)

                # Verificar se a tile que o servidor me deu é de facto a que originou o pseudónimo
                # que lhe enviei. Para isso utilizo o Ki do (Ki,Ti) recebido e calculo novamente
                # o pseudónimo.
                print(info)
                print(self.player.hand[i])
                Ki = bytes.fromhex(info[0])
                dk = hashlib.sha256()
                dk.update(str(info[1]).encode('utf-8'))
                dk.update(Ki)
                res = dk.hexdigest()
                print(res)
                if res != self.player.hand[i][1]:
                    print(Colors.BRed + "Server gave me the wrong tile on my de-anonymization request! (checked with received Ki)" + Colors.Color_Off)
                    exit(-1)
                print(Colors.BCyan+"Tile received from server verified by using the received Ki."+Colors.Color_Off)

                if info[1] < 10:
                    self.player.hand[i] = Piece(str(info[1])[0], 0)
                else:
                    self.player.hand[i] = Piece(str(info[1])[0], str(info[1])[1])
                i += 1

            for tile in self.player.hand:
                print(str(tile))
            interrupt("^^ Tiles na mão ^^")

            msg = {"action": "ready_to_play"}
            hmac = security_utils.hmac_sha512(msg, self.getSessionKey("server"))
            msg.update({"sentby": self.player.name, "hmac": hmac})
            self.sock.send(pickle.dumps(msg))

        elif action == "get_initial_pieces":
            #input("get piece\n\n")
            self.player.deck = data["deck"]
            pass_play=random.randint(0,100)
            if pass_play > 94:
                if len(self.player.hand) != 5:
                    #print(Colors.BGreen+"Press Enter \n\n"+Colors.Color_Off)
                    random.shuffle(self.player.deck)
                    piece = self.player.deck.pop()
                    self.player.insertInHand(piece)
                    print(Colors.BGreen+"Picked tile: ["+piece[0]+", ...]"+Colors.Color_Off)
                else:
                    interrupt(Colors.BGreen+"Hand already full.\n\n"+Colors.Color_Off)
            else:
                if pass_play > 50 and len(self.player.hand)>0:
                    remove_pieces = random.randint(1, len(self.player.hand))
                    random.shuffle(self.player.deck)
                    for i in range(0,remove_pieces):
                        piece = self.player.deck.pop()
                        to_insert= self.player.hand.pop(0)
                        self.player.insertInHand(piece)
                        self.player.updatePieces(-1)
                        self.player.deck.insert(0,to_insert)
                    print(Colors.BGreen+"Traded "+Colors.Color_Off+Colors.BICyan+str(remove_pieces)+Colors.Color_Off+Colors.BGreen+" tiles."+Colors.Color_Off)
                else:
                    print(Colors.BGreen+"Pass"+Colors.Color_Off)

            if len(self.player.deck) == int(28 -(self.player.pieces_per_player * self.player.nplayers)):
                pass_play = random.randint(0, 100)
                if pass_play > 94:
                    msg = {"action": "players_with_all_pieces", "deck": self.player.deck}
                    hmac = security_utils.hmac_sha512(msg, self.getSessionKey('server'))
                    msg.update({"sentby": self.player.name, "hmac": hmac})
                    self.sock.send(pickle.dumps(msg))
                    return

            interrupt("Sent message to the next player")
            sdeck = []
            for tile in self.player.deck:
                sdeck.append([tile[0],base64.b64encode(tile[1]).decode('ascii')])
            self.player.deck =sdeck
            to_send = {"action": "get_initial_pieces", "deck": self.player.deck}
            next_player = random.choice(self.player.opponents)#self.player.opponents[0]
            dh = next_player["dh"]

            hmac = security_utils.hmac_sha512(to_send, self.getSessionKey(next_player['name']))
            to_send.update({"sentby": self.player.name, "hmac": base64.b64encode(hmac).decode('ascii')})

            to_send = security_utils.toBytes(json.dumps(to_send))
            cyphred = security_utils.cipherSymKey(dh.full_key, to_send)

            msg = {"action": "send_to", "player_name": next_player["name"],
                   "sent_by": self.player.name, "msg": cyphred}

            hmac = security_utils.hmac_sha512(msg, self.getSessionKey('server'))
            msg.update({"sentby": self.player.name, "hmac": hmac})
            self.sock.send(pickle.dumps(msg))

        elif action == "rcv_game_propreties":
            self.player.deck = data["deck"]
            player_name = data["next_player"]
            self.player.in_table = data["in_table"]

            if data["next_player"] == self.player.name:
                player_name = Colors.BRed + "YOU" + Colors.Color_Off
            #print("deck -> " + ' '.join(map(str, self.player.deck)) + "\n")
            print("deck -> " + str(len(self.player.deck)) +" tiles remaining in the deck.")
            print("hand -> " + ' '.join(map(str, self.player.hand)))
            print("in table -> " + ' '.join(map(str, data["in_table"])) + "\n")
            print("Current player ->", player_name)
            print("next Action ->", data["next_action"])

            if data["next_player"] == self.player.name:
                if data["next_action"]=="play":
                    self.player.sortHand()
                    #input(Colors.BGreen+"Press Enter \n\n"+Colors.Color_Off)
                    print(Colors.BGreen+"Press Enter \n\n"+Colors.Color_Off)

                    if cheat:
                        msg = self.player.playCheat()
                    else:
                        msg = self.player.play()

                    if msg["action"] == "draw_piece":
                        self.player.drawntile = msg["tile"]
                        print(Colors.BGreen + "Drawn tile: " + Colors.Color_Off, self.player.drawntile)
                        interrupt("DRAWN TILE")

                    self.sock.send(pickle.dumps(msg))

        elif action == "get_drawntile_tilekeys":
            drawntile_tilekeys = data["tilekeys"]
            drawntile = data["tile"]

            for tilekey in drawntile_tilekeys:
                if tilekey != None:
                    tileDecoded = AESGCM(tilekey).decrypt(drawntile[1][:12], drawntile[1][12:],b"")  # Decrypt (raises InvalidTag if using wrong key or corrupted ciphertext)
                    drawntile = [drawntile[0], tileDecoded]

            for key in self.player.tilekeys:
                if key[1] == drawntile[1]:
                    drawntile_tilekeys.append(key[0])

            msg = {"action": "draw_piece", "tilekeys": drawntile_tilekeys, "tile": data["tile"]}
            hmac = security_utils.hmac_sha512(msg, self.getSessionKey("server"))
            msg.update({"sentby": self.player.name, "hmac": hmac})
            self.sock.send(pickle.dumps(msg))

        elif action == "rcv_drawntile_tilekeys":
            for key in data["all_tilekeys"]:
                tileDecoded = AESGCM(key).decrypt(self.player.drawntile[1][:12], self.player.drawntile[1][12:],b"")  # Decrypt (raises InvalidTag if using wrong key or corrupted ciphertext)
                self.player.drawntile = [self.player.drawntile[0], tileDecoded]

            self.player.drawntile = self.player.drawntile[1].decode('utf-8')
            self.player.drawntile = ast.literal_eval(self.player.drawntile)

            msg = {"action": "deanon_drawntile", "tile": self.player.drawntile}
            self.sock.send(pickle.dumps(msg))

        elif action == "rcv_deanon_drawntile":
            deanon_tile = data["tile"]

            #Verificar se a tile que o servidor me deu é de facto a que originou o pseudónimo
            #que lhe enviei. Para isso utilizo o Ki do (Ki,Ti) recebido e calculo novamente
            #o pseudónimo.
            print(deanon_tile)

            Ki = bytes.fromhex(deanon_tile[0])
            dk = hashlib.sha256()
            dk.update(str(deanon_tile[1]).encode('utf-8'))
            dk.update(Ki)
            res = dk.hexdigest()
            if res != self.player.drawntile[1]:
                print(Colors.BRed+"Servidor deu a tile errada no pedido de de-anonimização!"+Colors.Color_Off)
                exit(-1)
            print(Colors.BCyan + "Peça enviada pelo servidor verificada através do Ki." + Colors.Color_Off)

            if deanon_tile[1] < 10:
                deanon_tile = Piece(str(deanon_tile[1])[0], 0)
            else:
                deanon_tile = Piece(str(deanon_tile[1])[0], str(deanon_tile[1])[1])

            self.player.insertInHand(deanon_tile)
            self.player.sortHand()

            print("deck -> " + str(len(self.player.deck)) + " tiles remaining in the deck.")
            print("hand -> " + ' '.join(map(str, self.player.hand)))
            print("in table -> " + ' '.join(map(str, self.player.in_table)) + "\n")

            if cheat:
                msg = self.player.playCheat()
            else:
                msg = self.player.play()

            if msg["action"] == "draw_piece":
                self.player.drawntile = msg["tile"]
                print(Colors.BGreen+"Drawn tile: "+Colors.Color_Off,self.player.drawntile)
                interrupt("DRAWN TILE")

            self.sock.send(pickle.dumps(msg))




        elif action == "end_game":
            winner = data["winner"]
            if data["winner"] == self.player.name:
                winner = Colors.BRed + "YOU" + Colors.Color_Off
            else:
                winner = Colors.BBlue + winner + Colors.Color_Off
            print(Colors.BGreen + "End GAME, THE WINNER IS: " + winner)
            
            
            ######## BEGIN CITIZEN CARD CLAIM POINTS ###########
            
            # Claim Points (CITIZEN CARD)
    
            # 'n' - Don't Save Score / 'y' - Save Score with CC
            save = 'n'
            
            # Player Score
            score =  self.player.score
            
            # Player Nickname
            nickName = self.player.name
            
            # Player Slot
            playerSlot = -1
            
            save = input("Do you want to save your Score? => ")[0]
            
            if save == 'y':
                try:
                    cc = cc_utils.CitizenCard()
                except:
                    print("No Claim of Points Made!") 
                else:
                    try:    
                        if len(cc.sessions) > 0:
                            fullName = ''.join('Player{:3d} -> {:10s}\n'.format(i, cc.fullNames[i]) for i in range(0, len(cc.fullNames)))

                            while playerSlot < 0 or playerSlot > len(cc.sessions):
                                playerSlot = input("\nAvailable Player(s): \n{:40s}\nSign Points with Player => ".format(fullName))[0]
                                if playerSlot.isdigit():
                                    playerSlot = int(playerSlot)
                                else:
                                    playerSlot = 0
                        else:
                            logging.error("CC Not Found, insert it and try again!")
                            print("No Claim of Points Made!") 
                            return None
                            
                        # Get Certificate of the CC Player
                        cert = cc.getCCCert(playerSlot)

                        # Validate Certificate in the Chain of Trust
                        if(cc.validateChain(cert)):
                            print("Certificate Valid!\n")
                        else:
                            print("Certificate Invalid!\n")
                            return None
                        
                        # Login
                        cc.login(playerSlot)

                        # Data to be Signed - Name of the Player <-> Score            
                        jsonData = { "nickName" : nickName, "points" : score }
                        
                        # Sign Data -> signature
                        signature = cc.signData(json.dumps(jsonData), playerSlot)
                        print("Signature:  "+str(signature))
                        print("Cert:  "+str(cert))
                        signatureStr = base64.b64encode(signature).decode('ascii')
                        certStr = base64.b64encode(cert).decode('ascii')
                        
                        self.sock.send(pickle.dumps({"action":"signatureVerification", 
                                                    "info":{
                                                        "data" : json.dumps(jsonData) , 
                                                        "signature" : signatureStr , 
                                                        "certificate" : certStr
                                                    }}))                        
        
                    except KeyboardInterrupt:
                        # Logout
                        cc.logout(playerSlot)
                        cc.sessions[playerSlot].closeSession()
                        print("No Claim of Points Made!") 

                    else:
                        # Logout
                        cc.logout(playerSlot)
                        cc.sessions[playerSlot].closeSession()
                        print("Session Closed!") 
            
            else:
                print("No Claim of Points Made!")                  
            
            ######## END CITIZEN CARD SECTION ###########
            
            
            
            
        elif action == "validate":

            if self.player.notvalidate:
                self.player.forcevalidate = self.player.forcevalidate + 1
            tileplayed = data["tileplayed"]
            for tile in self.player.hand:
                if tile == tileplayed or self.player.forcevalidate == 2:
                    self.sock.send(pickle.dumps({"action":"validate", "status":"not_ok", "reason":"in_hand",
                                                 "msg": self.bitcommitment_msg, "key": self.bitcommitment_key,
                                                 "result":self.bitcommitment_res, "tile":tileplayed}))
                    print("This piece is in my hand")
                    return

            print("This piece is not in my hand")
            msg = {"action": "validate", "status": "ok"}
            hmac = security_utils.hmac_sha512(msg, self.getSessionKey("server"))
            msg.update({"sentby": self.player.name, "hmac": hmac})
            self.sock.send(pickle.dumps(msg))


        elif action == "validate_bit_commitment":
            key = data["key"]
            to_commit = data["msg"]
            commited = data["result"]
            saved_commit = None

            # check if all commitments remain the same
            for commit in self.all_bitcommitments:
                if commit[1] == commited:
                    saved_commit = commit

            if saved_commit is None:
                print("No saved commit matches this one.")
                sys.exit(-1)
            # verify commitments
            encoded_value = (to_commit + key).encode()
            to_check = sha256(encoded_value).hexdigest()
            if to_check == saved_commit[1] and to_check == commited:
                return self.sock.send(pickle.dumps({"action":"commitment_validated"}))
            else:
                return self.sock.send(pickle.dumps({"action":"commitment_wrong"}))

        elif action == "protest_all_tile":
            self.sock.send(pickle.dumps({"action": "send_all_tile_keys", "keys": self.player.tilekeys}))

        elif action == "wait":
            print(data["msg"])

        elif action =="disconnect":
            print(data['msg'])
            self.sock.close()
            sys.exit(0)

nickname_arg = None
cheat = 0

try:
    for i, arg in enumerate(sys.argv):
        if arg == "-nick":
            if sys.argv[i+1].startswith("-"):
                raise Exception
            nickname_arg = sys.argv[i+1]
        if arg == "-cheat":
            cheat = 1
except:
    print(Colors.Red+"Usage python3 client.py -nick NICK [-cheat] | Proceeding with default values"+Colors.Color_Off)


a = client('localhost', 50000, cheat, nickname_arg)
