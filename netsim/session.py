
class Session:
    partner = ''
    key = ''
    sqn_snd = 0
    sqn_rcv = 0

    def __init__(self, partner, key):
        self.partner = partner
        self.key = key

    def print(self):
        print('Session partner', self.partner)
        print('Session key', self.key)
        print('sqn_snd', self.sqn_snd)
        print('sqn_rcv', self.sqn_rcv)
