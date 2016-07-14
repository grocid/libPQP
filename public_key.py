class PublicKey:
    
    def __init__(self):    
        self.block_length = 4801 # this is insecure, but OK for tests 
        self.block_weight = 45
        self.block_error = 42
        
        self.G = []

    