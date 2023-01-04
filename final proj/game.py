from deck_utils import Deck,Player
import Colors

class Game:
    def __init__(self,max_players):
        self.deck = Deck()
        print("Deck created \n",self.deck)
        self.max_players = max_players
        self.nplayers = 0
        self.players = []
        self.player_index = 0
        self.init_distribution = True
        self.next_action="get_piece"
        self.started = False
        self.all_ready_to_play = False
        self.validateCounter = 0
        self.keys = {}
        self.all_tile_keys_counter = 0
        self.all_tilekeys = [None] * self.max_players
        self.protest_info = {}
        self.game_log = []
        self.cert = None

    def allPlayersWithSessions(self):
        return all([player.all_sessions for player in self.players])

    def checkDeadLock(self):
        return all([ player.nopiece for player in self.players ])

    def allPlayersWithPieces(self):
        return all([p.num_pieces == p.pieces_per_player for p in self.players])

    def currentPlayer(self):
        return self.players[self.player_index]

    def changeCurrentPlayer(self,socket):
        i = 0
        for player in self.players:
            if player.socket == socket:
                self.player_index = i
                return self.players[i]
            i += 1

    def previousPlayer(self):
        self.player_index -= 1
        if self.player_index == -1:
            self.player_index = self.max_players - 1
        return self.players[self.player_index]

    def nextPlayer(self):
        self.player_index +=1
        if self.player_index == self.max_players:
            self.player_index = 0
        return self.players[self.player_index]

    def addPlayer(self,name,socket,pieces):
        self.nplayers+=1
        assert  self.max_players>=self.nplayers
        player = Player(name,socket,pieces)
        print(player)
        self.players.append(player)

    def hasHost(self):
        return len(self.players)>0

    def hasPlayer(self,name):
        for player in self.players:
            if name == player.name:
                return True
        return False

    def isFull(self):
        return self.nplayers == self.max_players

    def toJson(self):
        msg = {"next_player":self.players[self.player_index].name ,"nplayers":self.nplayers
            ,"next_action":self.next_action}
        msg.update(self.deck.toJson())
        return msg