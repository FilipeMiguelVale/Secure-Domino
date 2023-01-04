import ast
import traceback

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from deck_utils import *
import socket
import select
import sys
import queue
import pickle
import hashlib
from hashlib import sha256
from game import Game
import signal
import Colors
import base64
from random import randint
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import security_utils
from security_utils import DH
import cc_utils
import json
import os.path

def interrupt(msg):
    return
    input(msg)

# Main socket code from https://docs.python.org/3/howto/sockets.html
# Select with sockets from https://steelkiwi.com/blog/working-tcp-sockets/

class TableManager:

    def __init__(self, host, port,nplayers=4):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #self.server.setblocking(False)  # non-blocking for select
        self.server.setblocking(0)
        self.server.bind((host, port))  # binding to localhost on 50000
        self.server.listen()
        self.game = Game(nplayers)  # the game associated to this table manager
        self.nplayers=nplayers
        print("Generating ASYM KEYS")
        #pub, priv = security_utils.createAsymKeys()

        cert,priv,pub=security_utils.gen_server_certificate(socket)
        self.game.cert = cert
        self.game.keys.update({"priv_key": priv, "pub_key": pub})
        print("Nplayers = ",nplayers)
        #disconnecting players when CTRL + C is pressed
        signal.signal(signal.SIGINT, self.signal_handler)
        #signal.pause()

        print("Server is On")

        # configuration for select()
        self.inputs = [self.server]  # sockets where we read
        self.outputs = []  # sockets where we write
        self.clientes = [] # clientes
        self.readytoplaycounter = 0
        self.startdecryptcounter = 0
        self.all_tilekeys = []
        self.all_bitcommitments = []
        self.initialdeck = []
        self.tileplayed = None

        self.message_queue = {}  # queue of messages

        self.pseudo_table = [None] * len(self.game.deck.deck)
        self.pseudo_deck = []
        self.deanon_array = [None] * len(self.game.deck.deck)
        self.startdeanonymizecounter = 0

        self.drawntile_tilekeys = []
        self.playerdrawingtile = None
        self.drawntile_index = None


        #pseudonymization
        for tile in range(0,len(self.game.deck.deck)):
            ix = int(self.game.deck.deck[tile][0])
            pwd = str(randint(00000, 99999))

            kdf = PBKDF2HMAC(hashes.SHA1(), 16, b'\x00', 1000, default_backend())
            Ki = kdf.derive(bytes(pwd, 'UTF -8'))

            self.pseudo_table[ix] = (Ki.hex(), self.game.deck.deck[tile][1].id(), False)

            dk = hashlib.sha256()
            dk.update(str(self.game.deck.deck[tile][1].id()).encode('utf-8'))
            dk.update(Ki)

            self.pseudo_deck.append([ix, dk.hexdigest()])

        print("PSEUDO TABLE: ")
        print(self.pseudo_table)
        print("PSEUDO DECK: ")
        print(self.pseudo_deck)
        self.game.deck.deck = self.pseudo_deck

        while self.inputs:
            readable, writeable, exceptional = select.select(self.inputs, self.outputs, self.inputs)
            for sock in readable:
                if sock is self.server:  # this is our main socket and we are receiving a new client
                    connection, ip_address = sock.accept()
                    print(Colors.BRed+"A new client connected -> "+Colors.BGreen+"{}".format(ip_address)+Colors.Color_Off)
                    connection.setblocking(False)
                    self.inputs.append(connection)  # add client to our input list
                    self.message_queue[connection] = queue.Queue()
                    self.clientes.append(connection)

                else:  # We are receiving data from a client socket
                    data = b''

                    while True:
                        # try:
                        packet = sock.recv(8192)
                        data += packet
                        if len(packet) < 8192:
                            break

                    while len(data) > 0:
                        if data:
                            try:
                                json_data = pickle.loads(data)
                                to_send = self.handle_action(data, sock)
                                data = data[len(pickle.dumps(json_data)):]

                            except Exception:
                                traceback.print_exc()
                                self.signal_handler(self, 0)
                            if to_send is not None:
                                self.message_queue[sock].put(to_send)  # add our response to the queue
                            if sock not in self.outputs:
                                self.outputs.append(sock)  # add this socket to the writeable sockets
                        else:
                            if sock in self.outputs:
                                self.outputs.remove(sock)
                            self.inputs.remove(sock)
                            sock.close()
                            del self.message_queue[sock]

            for sock in writeable:
                try:
                    to_send = self.message_queue[sock].get_nowait()
                except queue.Empty:  # Nothing more to send to this client
                    self.outputs.remove(sock)
                else:
                    sock.send(to_send)  # Send the info

            for sock in exceptional:  # if a socket is here, it has gone wrong and we must delete everything
                self.inputs.remove(sock)
                if sock in self.outputs:
                    self.outputs.remove(sock)
                sock.close()
                del self.message_queue[sock]

    def send_all(self, msg, socket=None, hmac=True):
        if socket is None:
            socket=self.server

        for sock in self.inputs:
            msg2 = {}
            msg2.update(msg)
            if sock is not self.server and sock is not socket :
                if hmac:
                    for p in self.game.players:
                        if p.socket == sock:
                            hmac = security_utils.hmac_sha512(msg2, p.keys['dh'].full_key)
                            msg2.update({"sentby": "server", "hmac": hmac})
                            break

                self.message_queue[sock].put(pickle.dumps(msg2))
                if sock not in self.outputs:
                    self.outputs.append(sock)

    def send_client(self, msg, socket,hmac=True):
        if hmac:
            for p in self.game.players:
                if p.socket == socket:
                    hmac = security_utils.hmac_sha512(msg, p.keys['dh'].full_key)
                    msg.update({"sentby": "server", "hmac": hmac})

        self.message_queue[socket].put(pickle.dumps(msg))
        if socket not in self.outputs:
            self.outputs.append(socket)


    def send_host(self,msg):
        for p in self.game.players:
            if p.socket == self.game.host_sock:
                hmac = security_utils.hmac_sha512(msg, p.keys['dh'].full_key)
                msg.update({"sentby": "server", "hmac": hmac})

        self.message_queue[self.game.host_sock].put(pickle.dumps(msg))
        if self.game.host_sock not in self.outputs:
            self.outputs.append(self.game.host_sock)

    def getSessionKey(self,name):
        key = ''
        for p in self.game.players:
            if p.name == name:
                key = p.keys["dh"].full_key
                break
        return key

    def confirmHmac(self, msg, sentby, hmac):
        key = self.getSessionKey(sentby)

        calcHMAC = security_utils.hmac_sha512(msg,key)
        if calcHMAC == hmac:
            print(Colors.BYellow + "Verified HMAC of message sent by "+Colors.Color_Off + sentby)
            #input("Verified")
            return True
        return False

    def handle_action(self, data, sock):
        data = pickle.loads(data)
        if "hmac" in data:
            sentby = data["sentby"]
            hmac = data["hmac"]
            data.pop("sentby")
            data.pop("hmac")
            if not self.confirmHmac(data, sentby, hmac):
                print(Colors.BRed + "Invalid HMAC, integrity compromised. Aborting game." + Colors.Color_Off)
                exit(-1)
        action = data["action"]
        print("\n"+action)
        if data:
            if action == "hello":
                msg = {"action": "login", "msg": "Welcome to the server, what will be your name?",
                       "server_cert":self.game.cert}
                return pickle.dumps(msg)

            if action == "req_login":
                msg = security_utils.decipherAsymKey(self.game.keys["priv_key"],data["msg"])
                data = json.loads(msg)
                data["pub_key"] = base64.b64decode(data["pub_key"].encode('ascii'))

                print("User {} requests login, with nickname {}".format(sock.getpeername(), data["msg"]))
                if not self.game.hasHost():  # There is no game for this tabla manager
                    self.game.addPlayer(data["msg"],sock,self.game.deck.pieces_per_player) # Adding host
                    dh = DH()
                    self.game.players[0].keys.update({"pub_key":data["pub_key"],"dh": dh})
                    cyphred = security_utils.cipherAsymKey(self.game.players[0].keys["pub_key"], dh.pulicKeyToPEM())
                    msg = {"action": "server_dh_negotiations", "action1": "you_host", "msg": Colors.BRed+"You are the host of the game"+Colors.Color_Off, "dh_key":cyphred }
                    print("User "+Colors.BBlue+"{}".format(data["msg"])+Colors.Color_Off+" has created a game, he is the first to join")
                    #interrupt("Press Enter")
                    return pickle.dumps(msg)
                else:
                    if not self.game.hasPlayer(data["msg"]):
                        if self.game.isFull():
                            msg = {"action": "full", "msg": "This table is full"}
                            print("User {} tried to join a full game".format(data["msg"]))
                            return pickle.dumps(msg)
                        else:
                            self.game.addPlayer(data["msg"], sock,self.game.deck.pieces_per_player)  # Adding player
                            dh = DH()
                            self.game.players[self.game.nplayers-1].keys.update({"pub_key": data["pub_key"], "dh": dh})
                            cyphred = security_utils.cipherAsymKey(self.game.players[self.game.nplayers-1].keys["pub_key"],
                                                                   dh.pulicKeyToPEM())
                            msg = {"action": "server_dh_negotiations", "action1": "","dh_key": cyphred}
                            print("User " + Colors.BBlue + "{}".format(
                                data["msg"]) + Colors.Color_Off + " has created a game, he is the first to join")
                            self.send_client(msg,sock,hmac=False)
                            msg = {"action": "new_player", "msg": "New Player "+Colors.BGreen+data["msg"]+Colors.Color_Off+" registered in game",
                                   "nplayers": self.game.nplayers, "game_players": self.game.max_players}
                            print("User "+Colors.BBlue+"{}".format(data["msg"])+Colors.Color_Off+" joined the game")
                            #interrupt("Press Enter")
                            #send info to all players
                            self.send_all(msg,hmac=False)


                            return pickle.dumps(msg)
                    else:
                        msg = {"action": "disconnect", "msg": "You are already in the game"}
                        print("User {} tried to join a game he was already in".format(data["msg"]))
                        return pickle.dumps(msg)

            if action == "reply_dh_negotiations":
                index = 0
                for i,player in enumerate(self.game.players):
                    if sock==player.socket:
                        index = i
                        break
                pub_key = security_utils.decipherAsymKey(self.game.keys["priv_key"], data["dh_key"]).encode('utf-8')
                dh = self.game.players[index].keys["dh"]
                dh.loadPeerPubKey(pub_key, pem=False)
                dh.generate_partial_key()
                dh.generate_full_key()

                if all([player.keys["dh"].full_key!= None for player in self.game.players]):
                    for player in self.game.players:
                        print("\nPlayer "+Colors.BBlue+"{}".format(player.name)+Colors.Color_Off+
                              " session key: " + Colors.BYellow + "{}".format(
                            player.keys["dh"].full_key) + Colors.Color_Off)
                    if self.game.isFull():
                        #interrupt("Press Enter")
                        for i in range(0, len(self.clientes)):
                            self.all_tilekeys.append(None)
                            self.all_bitcommitments.append(None)
                        print(Colors.BIPurple + "The game is Full" + Colors.Color_Off)
                        #msg = {"action": ""}

                        players_info = []
                        for player in self.game.players:
                            print("Player " + Colors.BBlue + "{}".format(player.name) + Colors.Color_Off + ""
                                                                                                           " \nkeys: " + Colors.BYellow + "{}".format(
                                player.keys) + Colors.Color_Off)
                            players_info.append({"name": player.name, "pub_key": player.keys["pub_key"]})

                        msg = {"action": "receive_players_information",
                               "msg": Colors.BRed + "Receiving players information" + Colors.Color_Off,
                               "players": players_info}
                        self.send_all(msg)

                        return pickle.dumps({"action":""})


            if action == "dh_sessions_finished":
                for player in self.game.players:
                    if sock==player.socket:
                        player.all_sessions = True
                        break
                if self.game.allPlayersWithSessions():
                    msg = {"action": "waiting_for_host",
                           "msg": Colors.BRed + "Waiting for host to start the game" + Colors.Color_Off}
                    msg.update(self.game.toJson())
                    self.send_all(msg)

            if action == "send_to":
                player_to_send = None
                for player in self.game.players:
                    if data["player_name"]==player.name:
                        player_to_send = player
                        break

                msg = {"action": "rcv_from_player","sent_by":data["sent_by"],"msg":data["msg"]}
                self.send_client(msg,player_to_send.socket)

                return  pickle.dumps({"action":""})

            if action == "send_to_unencrypted":
                player_to_send = None
                for player in self.game.players:
                    if data["player_name"]==player.name:
                        player_to_send = player
                        break

                msg = {"action": "rcv_from_player_unencrypted","sent_by":data["sent_by"],"msg":data["msg"]}
                self.send_client(msg,player_to_send.socket)

                return  pickle.dumps({"action":""})

            player = self.game.currentPlayer()

            if action == "start_game" and sock == player.socket:
                msg = {"action": "host_start_game", "msg": Colors.BYellow+"The Host started the game"+Colors.Color_Off}

                self.send_all(msg,sock)
                aux = []
                for tile in self.game.deck.deck:
                    aux.append(bytes(str(tile), encoding='utf-8'))
                self.game.deck.deck = aux
                msg = {"action": "encrypt_deck"}
                msg.update(self.game.toJson())

                hmac = security_utils.hmac_sha512(msg,self.getSessionKey(player.name))
                msg.update({"sentby":"server", "hmac":hmac})
                return pickle.dumps(msg)
                #return pickle.dumps(msg)

            if action == "encryption_done" and sock == self.game.players[0].socket:
                print('\n')
                print(Colors.BCyan+'All players have encrypted the deck'+Colors.Color_Off)
                #input(Colors.BBlue+"Press enter to continue..."+Colors.Color_Off)

                self.game.deck.deck = data["deck"]

                for i in range(0, len(self.game.deck.deck)):
                    self.game.deck.deck[i] = [str(i), self.game.deck.deck[i]]
                print(self.game.deck.deck)

                self.initialdeck = self.game.deck.deck

                clienterandom = random.choice(self.clientes)

                msg2 = {"action": "get_initial_pieces"}
                msg2.update(self.game.toJson())

                clienterandom_name = ''
                for cliente in self.game.players:
                    if cliente.socket == clienterandom:
                        clienterandom_name = cliente.name

                self.send_client(msg2, clienterandom)
                return pickle.dumps({"action":""})

            if action == "players_with_all_pieces":
                self.game.deck.deck = data["deck"]
                if len(self.game.deck.deck) == int(28-(self.game.deck.pieces_per_player * self.game.nplayers)):
                    #pedir bit commitment
                    msg = {"action": "get_bitcommitment"}

                    self.send_all(msg,sock)

                    for p in self.game.players:
                        if p.socket == sock:
                            hmac = security_utils.hmac_sha512(msg, p.keys['dh'].full_key)
                            msg.update({"sentby": "server", "hmac": hmac})
                            break

                    return pickle.dumps(msg)

            if action == "rcv_bitcommitment":
                index = 0
                for i in range(0,len(self.clientes)):
                    if sock == self.clientes[i]:
                        index = i

                self.all_bitcommitments[index] = (self.game.players[index].name,data["bitcommitment"])
                if (len(self.all_bitcommitments)-self.all_bitcommitments.count(None)) == len(self.clientes):
                    msg = {"action": "rcv_info", "all_bitcommitments": self.all_bitcommitments, "initialdeck": self.initialdeck}
                    self.send_all(msg, sock)

                    for p in self.game.players:
                        if p.socket == sock:
                            hmac = security_utils.hmac_sha512(msg, p.keys['dh'].full_key)
                            msg.update({"sentby": "server", "hmac": hmac})
                            break

                    return pickle.dumps(msg)

            if action == "start_decrypt":
                self.startdecryptcounter += 1

                if self.startdecryptcounter >= len(self.clientes):
                    self.game.previousPlayer()
                    player = self.game.currentPlayer()

                    if self.startdecryptcounter == len(self.clientes):
                        #meter o game current player no ultimo
                        self.game.changeCurrentPlayer(self.clientes[-1])
                        player = self.game.currentPlayer()

                    if "all_tilekeys" in data:
                        self.all_tilekeys = data["all_tilekeys"]

                    if self.startdecryptcounter != len(self.clientes) and self.game.currentPlayer().socket == self.clientes[-1]:
                        msg = {"action": "decrypt_hand", "all_tilekeys": self.all_tilekeys}
                        msg.update(self.game.toJson())
                        self.send_all(msg,sock)
                        for p in self.game.players:
                            if p.socket == sock:
                                hmac = security_utils.hmac_sha512(msg, p.keys['dh'].full_key)
                                msg.update({"sentby": "server", "hmac": hmac})
                                break
                        return pickle.dumps(msg)

                    msg2 = {"action": "get_tilekeys", "all_tilekeys": self.all_tilekeys}
                    msg2.update(self.game.toJson())
                    self.send_client(msg2, player.socket)
                else:
                    msg = {"action": "wait", "msg": "Waiting for other players to confirm info..."}
                    self.send_all(msg)
                    return pickle.dumps({"action":""})

            if action == "answer_tilekeys":
                index = 0
                for i in range(0, len(self.clientes)):
                    if sock == self.clientes[i]:
                        index = i

                self.all_tilekeys[index]=data["tilekeys"]
                if (len(self.all_tilekeys)-self.all_tilekeys.count(None)) == len(self.clientes):
                    msg = {"action": "decrypt_hand","all_tilekeys": self.all_tilekeys}
                    self.send_all(msg)

                    return pickle.dumps({"action":""})

            if action == "deanonymize":
                self.startdeanonymizecounter += 1
                if self.startdeanonymizecounter >= len(self.clientes):
                    msg2 = {"action": "deanonymize", "de_anon": self.deanon_array}
                    self.send_client(msg2, random.choice(self.clientes))
                    return pickle.dumps({"action":""})
                else:
                    msg = {"action": "wait", "msg": "Waiting for other players to finish decrypting..."}
                    return pickle.dumps(msg)

            if action == "done_deanonymize":
                self.deanon_array = data["de_anon"]
                for i,deanon in enumerate(self.deanon_array):
                    if self.deanon_array[i] != None:
                        self.deanon_array[i] = base64.b64decode(deanon.encode('ascii'))
                        self.deanon_array[i] = security_utils.cipherAsymKey(self.deanon_array[i],self.pseudo_table[i])
                        self.pseudo_table[i] = (self.pseudo_table[i][0],self.pseudo_table[i][1],True)

                print(Colors.BYellow+'pseudo_table '+Colors.Color_Off,self.pseudo_table)
                print(Colors.BYellow+'deanon_array '+Colors.Color_Off,self.deanon_array)

                interrupt(Colors.BCyan+"Sending this answer... Press Enter..."+Colors.Color_Off)

                for player in self.game.players:
                    player.num_pieces = player.pieces_per_player

                msg = {"action": "rcv_deanonymize", "de_anon": self.deanon_array}
                self.send_all(msg)
                return pickle.dumps({"action":""})

            if action == "ready_to_play":
                self.readytoplaycounter += 1

                if self.readytoplaycounter == len(self.clientes):
                    self.game.changeCurrentPlayer(self.clientes[0])
                    self.game.started = True
                    self.game.next_action = "play"
                    msg = {"action": "rcv_game_propreties"}
                    msg.update(self.game.toJson())
                    self.send_all(msg)
                else:
                    msg = {"action": "wait","msg": "Waiting for other players to decrypt..."}
                    self.send_client(msg,sock)
                    return pickle.dumps(msg)

            if action == "play_piece":

                if data["piece"]is not None:
                    self.tileplayed = data["piece"]
                    player.nopiece = False
                    player.updatePieces(-1)
                    if data["edge"]==0:
                        self.game.deck.in_table.insert(0,data["piece"])
                    else:
                        self.game.deck.in_table.insert(len(self.game.deck.in_table),data["piece"])

                    print("player pieces ", player.num_pieces)
                    print("player " + player.name + " played " + str(data["piece"]))
                    print("in table -> " + ' '.join(map(str, self.game.deck.in_table)) + "\n")
                    print("deck -> " + str(len(self.game.deck.deck)) + " tiles remaining in the deck.")
                    msg = {"action": "validate", "tileplayed": self.tileplayed}
                    self.send_all(msg)
                    return pickle.dumps({"action":""})

                else:
                    print("player pieces ", player.num_pieces)
                    print("player " + player.name + " played " + str(data["piece"]))
                    print("in table -> " + ' '.join(map(str, self.game.deck.in_table)) + "\n")
                    print("deck -> " + str(len(self.game.deck.deck)) + " tiles remaining in the deck.")

                    self.game.nextPlayer()
                    msg = {"action": "rcv_game_propreties"}
                    msg.update(self.game.toJson())
                    self.send_all(msg)
                    return pickle.dumps({"action":""})

            if action == "draw_piece":
                if "deck" in data:
                    self.drawntile_tilekeys = []
                    self.game.deck.deck = data["deck"]
                    player.updatePieces(1)
                    self.playerdrawingtile = player
                    self.drawntile_index = len(self.clientes) - 1

                if "tilekeys" in data:
                    self.drawntile_tilekeys = data["tilekeys"]

                if self.drawntile_index == -1:
                    msg2 = {"action": "rcv_drawntile_tilekeys", "all_tilekeys": self.drawntile_tilekeys}
                    self.send_client(msg2, player.socket)

                else:
                    msg2 = {"action": "get_drawntile_tilekeys", "tile": data["tile"], "tilekeys": self.drawntile_tilekeys}
                    self.send_client(msg2, self.clientes[self.drawntile_index])
                    self.drawntile_index -= 1
                return pickle.dumps({"action":""})

            if action == "deanon_drawntile":
                curr_player = None
                for player in self.game.players:
                    if player.socket == sock:
                        curr_player = player
                        break
                drawntile = data["tile"]
                self.pseudo_table[drawntile[0]] = (self.pseudo_table[drawntile[0]][0],self.pseudo_table[drawntile[0]][1],True)
                to_send = {"action": "rcv_deanon_drawntile", "tile": self.pseudo_table[drawntile[0]]}
                self.game.game_log.append((self.clientes.index(sock), self.pseudo_table[drawntile[0]][1]))
                to_send = security_utils.toBytes(json.dumps(to_send))
                data2 = security_utils.cipherSymKey(curr_player.keys["dh"].full_key, to_send)
                msg = {"action":"rcv_from_server","msg":data2}
                for p in self.game.players:
                    if p.socket == sock:
                        hmac = security_utils.hmac_sha512(msg, p.keys['dh'].full_key)
                        msg.update({"sentby": "server", "hmac": hmac})
                        break
                return pickle.dumps(msg)

            if action == "signatureVerification":
                
                points = data["info"]["data"]
                cert = base64.b64decode(data["info"]["certificate"].encode('ascii'))
                signature = base64.b64decode(data["info"]["signature"].encode('ascii'))
                
                cc = cc_utils.CitizenCard()
                # Validate Certificate in the Chain of Trust
                if(cc.validateChain(cert)):
                    print("Certificate Valid!\n")
                else:
                    msg = {"action": "wait", "msg": "Certificate Invalid!"}
                    return pickle.dumps(msg)
                
                if (cc.signatureVerification(points, cert, signature)):
                                            
                    print("Identity Verified!")
                    print("Preparing to Save to JSON...")
                    
                    signatureStr = base64.b64encode(signature).decode('ascii')
                    certStr = base64.b64encode(cert).decode('ascii')
                    
                    jsonStr =  '{ "data" : ' + points + ', "signature" : \"' + signatureStr  + '\", "certificate" : \"' + certStr + '\" }'
                   
                    jsonFile = json.loads(jsonStr)
                    
                    # If File Exists
                    if os.path.exists('scores.json'):
                        # Read Data from JSON
                        with open('scores.json', 'r') as f:
                            dataJSON = json.load(f)
                            # Score Exists = False
                            exists = False
                            
                            for score in dataJSON['scores']: 
                                
                                print(dataJSON['scores'])
                                print(score)
                                print(score["data"]["nickName"])
                                print(jsonFile["data"]["nickName"])
                                
                                if score["certificate"] == jsonFile["certificate"]:
                                    # If nickName and certificate corresponds -> Update
                                    if score["data"]["nickName"] == jsonFile["data"]["nickName"]:
                                        dataJSON["scores"][dataJSON['scores'].index(score)]["data"]["points"] = score["data"]["points"] +jsonFile["data"]["points"]
                                        print("Score Updated!")
                                        exists = True
                                        break
                                    # Case not
                                    else:
                                        msg = {"action": "wait", "msg": "CC Identify already exists!"}
                                        return pickle.dumps(msg)
                            # If Score does not Exists 
                            if not exists:   
                                dataJSON["scores"].append(jsonFile)
                                print("Score Added!")
                            f.close()
                            
                        # Write to JSON  
                        with open('scores.json', 'w') as f:
                            json.dump(dataJSON, f)
                            f.close()
                            
                        print("Json Updated!")
                            
                    # If File does not Exists 
                    else:
                        with open('scores.json', 'w') as f:
                            # Create first Score
                            dataJSON = {"scores" : [jsonFile]}
                            json.dump(dataJSON, f)
                            f.close()
                        print("Json Created!")
                    
                    msg = {"action": "wait", "msg": "Score Verified and Stored!"}
                    return pickle.dumps(msg)

            if action == "validate":
                if data["status"] == "ok":
                    print("This play was validated by " + str(self.game.validateCounter+1) + " clients")
                    if self.game.validateCounter == NUM_PLAYERS - 1:

                        # verificar se há outra peça igual na table
                        lista = [piece.id() for piece in self.game.deck.in_table]
                        print(lista)
                        if len(lista) != len(set(lista)):
                            print("This play was not validated BY THE SERVER")
                            print("Cheater: " + player.name)
                            print("Tile used to cheat:" + str(self.tileplayed))
                            msg = {"action": "disconnect", "msg": Colors.BRed + "Game aborted." + Colors.Color_Off +
                                   " Cheater " + Colors.BBlue + player.name + Colors.Color_Off +
                                   " used tile " + str(self.tileplayed) + " that was already on table."}
                            self.send_all(msg)
                            return pickle.dumps({"action":""})

                        # verificar se a peça jogada ainda está no stock (pela pseudonym table)
                        tileid = self.tileplayed.id()
                        for triple in self.pseudo_table:
                            if triple[1] == tileid and triple[2] == False:
                                print("This play was not validated BY THE SERVER")
                                print("Cheater: " + player.name)
                                print("Tile used to cheat:" + str(self.tileplayed))
                                msg = {"action": "disconnect", "msg": Colors.BRed + "Game aborted." + Colors.Color_Off +
                                                                      " Cheater " + Colors.BBlue + player.name + Colors.Color_Off +
                                                                      " used tile " + str(
                                    self.tileplayed) + " that was still in the stock."}
                                self.send_all(msg)
                                return pickle.dumps({"action":""})

                        if player.checkifWin():
                            print(Colors.BGreen + " WINNER " + player.name + Colors.Color_Off)
                            
                            for loser in (p for p in self.game.players if p != player):
                                for piece in loser.hand:
                                    loser.score = loser.score - sum(piece.value)
                                    print("SCORE LOSER: "+ loser.name+" = "+str(loser.score))
                                
                            msg = {"action": "end_game", "winner": player.name}
                            msg.update(self.game.toJson())
                            self.send_all(msg)
                            return pickle.dumps({"action":""})

                        self.game.nextPlayer()
                        self.game.validateCounter = 0
                        msg = {"action": "rcv_game_propreties"}
                        msg.update(self.game.toJson())
                        self.send_all(msg)
                        return pickle.dumps({"action":""})
                    else:
                        self.game.validateCounter = self.game.validateCounter + 1
                else:
                    if data["reason"] == "in_hand":
                        self.game.protest_info["msg"] = data["msg"]
                        self.game.protest_info["key"] = data["key"]
                        self.game.protest_info["result"] = data["result"]
                        self.game.protest_info["tile"] = data["tile"]
                        self.game.protest_info["sock_id"] = self.clientes.index(sock)
                        #we need all tilekeys
                        self.send_all({"action": "protest_all_tile"})
                        return
                    else:
                        print("Something went wrong")
                return pickle.dumps({"action": ""})

            if action == "send_all_tile_keys":
                self.game.all_tilekeys[self.clientes.index(sock)] = data["keys"]
                if self.game.all_tile_keys_counter == NUM_PLAYERS - 1:
                    self.game.all_tilekeys.reverse()
                    for player_id, tilekeys in enumerate(self.game.all_tilekeys):
                        #print(tilekeys)
                        for i, tile in enumerate(self.initialdeck):
                            for key in tilekeys:
                                if key[1] == tile[1]:
                                    tileDecoded = AESGCM(key[0]).decrypt(key[1][:12], key[1][12:],
                                                                         b"")  # Decrypt (raises InvalidTag if using wrong key or corrupted ciphertext)
                                    self.initialdeck[i] = [tile[0], tileDecoded]
                                    print(Colors.BRed + "Tile " + str(i + 1) + " decrypted " + str(
                                        player_id + 1) + " times." + Colors.Color_Off)
                                    break
                    #verificar o bit commitment
                    encoded_value = (self.game.protest_info["msg"] + self.game.protest_info["key"]).encode()
                    to_check = sha256(encoded_value).hexdigest()
                    try:
                        index = [commit[1] for commit in self.all_bitcommitments].index(to_check)
                    except:
                        print("This bit commit is not one of the published ones")
                        print("This play was not validated BY THE SERVER")
                        print("Cheater: " + self.game.players[self.clientes.index(sock)].name)
                        print("Tile used to cheat:" + str(self.tileplayed))
                        msg = {"action": "disconnect", "msg": Colors.BRed + "Game aborted." + Colors.Color_Off +
                                                              " Cheater " + Colors.BBlue + self.game.players[self.clientes.index(sock)].name + Colors.Color_Off +
                                                              " did not provide valid values for his bitcommitment"}
                        self.send_all(msg, sock)
                        return pickle.dumps(msg)


                    indices = self.game.protest_info["msg"].split(",")

                    #check for tile in initial hand
                    for indice in indices:
                        tile_tmp = self.initialdeck[int(indice)]
                        tile_tmp[1] = ast.literal_eval(tile_tmp[1].decode('utf-8'))
                        hand_tile_id = self.pseudo_table[int(tile_tmp[1][0])][1]
                        if hand_tile_id == self.game.protest_info["tile"].id():
                            print("This play was not validated BY THE SERVER")
                            print("Cheater: " + player.name)
                            print("Tile used to cheat:" + str(self.tileplayed))
                            msg = {"action": "disconnect", "msg": Colors.BRed + "Game aborted." + Colors.Color_Off +
                                                                  " Cheater " + Colors.BBlue + player.name + Colors.Color_Off +
                                                                  " used tile " + str(
                                self.tileplayed) + " that another player had in his initial hand"}
                            self.send_all(msg)
                            return pickle.dumps({"action":""})
                    #check for tile in drawn tiles
                    print(self.game.game_log)
                    for tile_played in self.game.game_log:
                        print(self.clientes.index(sock))
                        if self.game.protest_info["sock_id"] == tile_played[0]:
                            print("here")
                            if tile_played[1] == self.game.protest_info["tile"].id():
                                print("This play was not validated BY THE SERVER")
                                print("Cheater: " + player.name)
                                print("Tile used to cheat:" + str(self.tileplayed))
                                msg = {"action": "disconnect", "msg": Colors.BRed + "Game aborted." + Colors.Color_Off +
                                                                      " Cheater " + Colors.BBlue + player.name + Colors.Color_Off +
                                                                      " used tile " + str(
                                    self.tileplayed) + " that another player had in his hand"}
                                self.send_all(msg)
                                return pickle.dumps({"action":""})

                    print("This protest was not validated BY THE SERVER")
                    print("Cheater: " + self.game.players[self.clientes.index(sock)].name)
                    print("Tile used to cheat:" + str(self.tileplayed))
                    msg = {"action": "disconnect", "msg": Colors.BRed + "Game aborted." + Colors.Color_Off +
                                                          " Cheater " + Colors.BBlue +
                                                          self.game.players[self.clientes.index(sock)].name + Colors.Color_Off +
                                                          " protested tile " + str(
                        self.tileplayed) + " that he did not have"}
                    self.send_all(msg)
                    return pickle.dumps({"action":""})
                else:
                    self.game.all_tile_keys_counter = self.game.all_tile_keys_counter + 1


            if action == "pass_play" and sock == player.socket:
                # verificar se o jogador deu pass quando devia ter dado draw
                if len(self.game.deck.deck) > 0:
                    print("This pass was not validated BY THE SERVER")
                    print("Cheater: " + player.name)
                    msg = {"action": "disconnect", "msg": Colors.BRed + "Game aborted." + Colors.Color_Off +
                                                          " " + Colors.BBlue + player.name + Colors.Color_Off +
                                                          " passed instead of drawing a tile from stock."}
                    self.send_all(msg)
                    return pickle.dumps({"action": ""})

                self.game.nextPlayer()
                #If the player passed the previous move

                if all([player.nopiece for player in self.game.players]):
                    print("No piece END")
                    msg = {"action": "end_game", "winner": Colors.BYellow+"TIE"+Colors.Color_Off}
                    self.send_all(msg)
                    return pickle.dumps({"action":""})

                #Update the variable nopiece so that the server can know if the player has passed the previous move
                else:
                    print("No piece")
                    player.nopiece = True
                    msg = {"action": "rcv_game_propreties"}
                    msg.update(self.game.toJson())
                    self.send_all(msg)
                    return pickle.dumps({"action":""})

            else:
                msg = {"action": "wait","msg":Colors.BRed+"Not Your Turn"+Colors.Color_Off}
                return pickle.dumps(msg)

    #Function to handle CTRL + C Command disconnecting all players
    def signal_handler(self,sig, frame):
        if sig == signal.SIGINT:
            print('You pressed Ctrl+C!')
        size = len(self.inputs)-1
        msg = {"action": "disconnect", "msg": "The server disconnected you"}
        i = 1
        for sock in self.inputs:
            if sock is not self.server:
                print("Disconnecting player " + str(i) + "/" + str(size))
                sock.send(pickle.dumps(msg))
                i+=1
            #return pickle.dumps(msg)
        print("Disconnecting Server ")
        self.server.close()
        sys.exit(0)

try:
    NUM_PLAYERS = int(sys.argv[1])
except:
    NUM_PLAYERS = 3
a = TableManager('localhost', 50000,NUM_PLAYERS)

