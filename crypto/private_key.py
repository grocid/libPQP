'''
This file is part of libPQP
Copyright (C) 2016 Carl Londahl <carl.londahl@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

class PrivateKey:
    
    def __init__(self):    
        self.block_length = 4801 # this is insecure, but OK for tests 
        self.block_weight = 45
        self.block_error = 42

        self.H_0 = []
        self.H_1 = []
        self.H_1inv = []