class PrivateKey:
    
    def __init__(self):    
        self.block_length = 4801 # this is insecure, but OK for tests 
        self.block_weight = 45
        self.block_error = 42

        self.H_0 = []
        self.H_1 = []
        self.H_1inv = []