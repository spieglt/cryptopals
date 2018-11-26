def bitSet(num, bit):
	if num & 2 ** bit == 2 ** bit:
		return True
	else: return False

print(bin(42))
for x in range(0,8):
	print(bitSet(89, x))
