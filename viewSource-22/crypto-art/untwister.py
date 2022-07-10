#!/usr/bin/env python
# sudo apt-get update
# sudo apt-get install python3-pip
# pip install z3-solver
from z3 import *

class mersenne_rng(object):
	def __init__(self, seed=5489):
		self.state = [0]*624
		self.f = 1812433253
		self.m = 397
		self.u = 11
		self.s = 7
		self.b = 0x9D2C5680
		self.t = 15
		self.c = 0xEFC60000
		self.l = 18
		self.index = 624
		self.lower_mask = (1 << 31)-1
		self.upper_mask = 1 << 31

		# update state
		self.state[0] = seed
		for i in range(1, 624):
			self.state[i] = self.int_32(
				self.f*(self.state[i-1] ^ (self.state[i-1] >> 30)) + i)

	def twist(self):
		for i in range(624):
			temp = self.int_32(
				(self.state[i] & self.upper_mask)+(self.state[(i+1) % 624] & self.lower_mask))
			temp_shift = temp >> 1
			if temp % 2 != 0:
				temp_shift = temp_shift ^ 0x9908b0df
			self.state[i] = self.state[(i+self.m) % 624] ^ temp_shift
		self.index = 0

	def temper(self, in_value):
		y = in_value
		y = y ^ (y >> self.u)
		y = y ^ ((y << self.s) & self.b)
		y = y ^ ((y << self.t) & self.c)
		y = y ^ (y >> self.l)
		return y

	def get_random_number(self):
		if self.index >= 624:
			self.twist()
		out = self.temper(self.state[self.index])
		self.index += 1
		return self.int_32(out)

	def int_32(self, number):
		return int(0xFFFFFFFF & number)


class untwister:
	def __init__(self):
		self.N = 624
		self.state = []
		self.cloned = None
		self.nums = []
		self.i = 0

	def untemper(self,out):
		"""
		This is the untemper function, i.e., the inverse of temper. This
		is solved automatically using the SMT solver Z3. I could prpbably
		do it by hand, but there is a certain elegance in untempering symbolically.
		"""
		y1 = BitVec('y1', 32)
		y2 = BitVec('y2', 32)
		y3 = BitVec('y3', 32)
		y4 = BitVec('y4', 32)
		y = BitVecVal(out, 32)
		s = Solver()
		equations = [
			y2 == y1 ^ (LShR(y1, 11)),
			y3 == y2 ^ ((y2 << 7) & 0x9D2C5680),
			y4 == y3 ^ ((y3 << 15) & 0xEFC60000),
			y == y4 ^ (LShR(y4, 18))
		]
		s.add(equations)
		s.check()
		return s.model()[y1].as_long()

	def untwist(self,numbers):
		self.state=[]
		self.nums.extend(numbers[0:self.N])
		for n in numbers[0:self.N]:
			self.state.append(self.untemper(n))
		return self.state

	def clone(self):
		print("Cloning ...")
		self.cloned = mersenne_rng()
		self.cloned.state = self.state
		print("Cloning Done ...")

	def replay(self):
		if self.i < self.N:
			res = self.nums[self.i]
			self.i+=1
			return res
		else:
			return self.cloned.get_random_number()

if __name__ == "__main__":
	rng = mersenne_rng(1337)
	print(f"Real intern state of PRNG: {rng.state[0:10]} ... ")
	random_nums = []	
	for i in range(624):
		random_nums.append(rng.get_random_number())
	print(f"Generated Number : {random_nums[0:10]} ...")
	untwist = untwister()
	recovered_state = untwist.untwist(random_nums)
	print(f"recovered internal state: {recovered_state[0:10]} ... ")
	untwist.clone()
	print("check equality of next 1000 outputs from the real and cloned rng")
	for i in range(1000):
		assert(untwist.cloned.get_random_number() == rng.get_random_number())
	print('Success!')

