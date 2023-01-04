import random


class Player:
    def __init__(self, name,socket,pieces_per_player=None):
        self.name = name
        self.socket = socket
        self.hand = []
        self.num_pieces = 0
        self.score = 0
        self.host=False
        self.pieces_per_player=pieces_per_player
        self.ready_to_play = False
        self.in_table = []
        self.deck = []
        self.nopiece = False
        self.tilekeys = []
        self.opponents=[]
        self.keys={}
        self.all_sessions = False
        self.drawntile = None
        self.firstencription = True
        self.notvalidate = False
        self.forcevalidate = 0

    def __str__(self):
        return str(self.toJson())

    def toJson(self):
        return {"name": self.name, "hand": self.hand, "score": self.score}

    def isHost(self):
        return self.host

    def pickPiece(self):
        if not self.ready_to_play and self.num_pieces==self.pieces_per_player:
            self.ready_to_play = True
        random.shuffle(self.deck)
        piece = self.deck.pop()
        return {"action": "draw_piece", "deck": self.deck, "tile":piece}

    def updatePieces(self,i):
        self.num_pieces+=i
        
    def updateScore(self,pieceValue):
        self.score = self.score + pieceValue

    def canPick(self):
        return self.num_pieces<self.pieces_per_player

    def insertInHand(self,piece):
        self.num_pieces += 1
        self.hand.append(piece)

    def sortHand(self):
        self.hand.sort(key=lambda p : int(p.values[0].value)+int(p.values[1].value))

    def checkifWin(self):
        print("Winner ",self.num_pieces == 0)
        return self.num_pieces == 0

    def playCheat(self):
        choice = input("Cheat(1) or Play Auto(2) (only this turn)")
        if choice == '1':
            while(True):
                cheatTile = input("Piece (ID/pass/draw/(protest) next move): ")
                if cheatTile == "pass":
                    return {"action": "pass_play", "piece": None, "win": self.checkifWin()}
                if cheatTile == "draw":
                    if len(self.deck) > 0:
                        return self.pickPiece()
                    else:
                        return {"action": "pass_play", "piece": None, "win": self.checkifWin()}
                if cheatTile == "protest":
                    self.notvalidate = True
                    return self.play()

                piece = Piece(cheatTile[0], cheatTile[1])

                edges = self.in_table[0].values[0].value, self.in_table[len(self.in_table) - 1].values[1].value

                edge = None
                flip = False
                if int(piece.values[0].value) == int(edges[0]):
                    flip = True
                    edge = 0
                elif int(piece.values[1].value) == int(edges[0]):
                    flip = False
                    edge = 0
                elif int(piece.values[0].value) == int(edges[1]):
                    flip = False
                    edge = 1
                elif int(piece.values[1].value) == int(edges[1]):
                    flip = True
                    edge = 1

                if edge is not None:
                    if flip:
                        piece.flip()

                for mytiles in self.hand:
                    if mytiles == piece:
                        self.hand.remove(mytiles)
                self.updatePieces(-1)
                self.updateScore(piece.value)
                print("SCORE: "+ self.name+" = "+str(self.score))
                res = {"action": "play_piece", "piece": piece,"edge":edge, "win": self.checkifWin()}
                return res
            else:
                print("Peça inválida, escreva outra")
        else:
            return self.play()

    def play(self):
        res = {}
        if self.in_table == []:
            print("Empty table")
            piece = self.hand.pop()
            self.updatePieces(-1)
            self.updateScore(piece.value)
            print("SCORE: "+ self.name+" = "+str(self.score))
            res = {"action": "play_piece","piece":piece,"edge":0,"win":False}
        else:
            edges = self.in_table[0].values[0].value, self.in_table[len(self.in_table) - 1].values[1].value
            print("Edges to play: "+str(edges[0])+" "+str(edges[1]))
            max = 0
            index = 0
            edge = None
            flip = False
            #get if possible the best piece to play and the correspondent assigned edge
            for i, piece in enumerate(self.hand):
                aux = int(piece.values[0].value) + int(piece.values[1].value)
                if aux >= max:
                    if int(piece.values[0].value) == int(edges[0]):
                            max = aux
                            index = i
                            flip = True
                            edge = 0
                    elif int(piece.values[1].value) == int(edges[0]):
                            max = aux
                            index = i
                            flip = False
                            edge = 0
                    elif int(piece.values[0].value) == int(edges[1]):
                            max = aux
                            index = i
                            flip = False
                            edge = 1
                    elif int(piece.values[1].value) == int(edges[1]):
                            max = aux
                            index = i
                            flip = True
                            edge = 1
            #if there is a piece to play, remove the piece from the hand and check if the orientation is the correct
            if edge is not None:
                piece = self.hand.pop(index)
                if flip:
                    piece.flip()
                self.updatePieces(-1)
                self.updateScore(piece.value)
                print("SCORE: "+ self.name+" = "+str(self.score))
                res = {"action": "play_piece", "piece": piece,"edge":edge,"win":self.checkifWin()}
            # if there is no piece to play try to pick a piece, if there is no piece to pick pass
            else:
                if len(self.deck)>0:
                    print("To play -> draw tile from stock")
                    return self.pickPiece()
                else:
                    print("To play -> PASS")
                    return {"action": "pass_play", "piece": None, "edge": edge,"win":self.checkifWin()}
            print("To play -> "+str(piece))
            #input("ENTER")
        return res

class Piece:
    values = []

    def __init__(self, first, second):
        self.values = [SubPiece(first), SubPiece(second)]
        self.first = int(first)
        self.second = int(second)
        self.value = int(first) + int(second)

    def __str__(self):
        return " {}:{}".format(str(self.values[0]),str(self.values[1]))

    def id(self):
        if self.first > self.second:
            return int(self.first)*10 + int(self.second)
        else:
            return int(self.second) * 10 + int(self.first)

    def flip(self):
        self.values = [self.values[1], self.values[0]]

    def __eq__(self, other):
        if (self.first == other.first and self.second == other.second) \
                or (self.first == other.second and self.second == other.first):
            return True

class SubPiece:
    value = None
    def __init__(self,value):
        self.value = value

    def __str__(self):
        return "\033[1;9{}m{}\033[0m".format(int(self.value)+1, self.value)

class Deck:

    deck = []

    def __init__(self,pieces_per_player=5):
        with open('pieces', 'r') as file:
            pieces = file.read()
        for piece in pieces.split(","):
            piece = piece.replace(" ", "").replace('\n',"").split("-")
            self.deck.append(Piece(piece[0], piece[1]))

        self.npieces = len(self.deck)
        self.pieces_per_player = pieces_per_player
        self.in_table = []

        random.shuffle(self.deck)
        for i in range(0,len(self.deck)):
            self.deck[i] = [str(i),  self.deck[i]]


    def __str__(self):
        a = ""
        for piece in self.deck:
            a+= "[" + piece[0] + ", " + str(piece[1]) + "]"
        return a

    def toJson(self):
        return {"npieces": self.npieces, "pieces_per_player": self.pieces_per_player, "in_table": self.in_table,"deck":self.deck}

