
class Session:
    partner = ''
    key = ''
    sqn_snd = 0
    sqn_rcv = 0

    def __init__(self, partner, key):
        self.partner = partner
        self.key = key
