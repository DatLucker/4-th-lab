class Server:
    def __init__(self):
        self.database = []

    def add(self, login, v, s):
        self.database.append((login,v,s))
        
