import sys

# Eager evaluation: allocates all 1,000,000 integers in RAM (~8.45 MB)
list_comp = [x * 2 for x in range(1_000_000)]

# Lazy evaluation: yields one item at a time on demand (208 bytes)
gen_exp = (x * 2 for x in range(1_000_000))

print("List bytes:", sys.getsizeof(list_comp))
print("Generator bytes:", sys.getsizeof(gen_exp))