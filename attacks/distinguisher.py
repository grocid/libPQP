class Distinguisher:

    def __init__(self, block_weight, block_error):        
        self.parity = (block_error + block_error) % 2
        
    def distinguish(self, c):
        if sum(list(c)) % 2 == self.parity:
            return True
        else:
            return False