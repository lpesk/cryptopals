from tools.message import Message
from tools.randomdata import randMsg

# example from the challenge statement
msg_str = "YELLOW SUBMARINE"

msg = Message(msg_str, 'ascii')
print("Original message:", repr(msg.ascii()))

msg.pad(block_size=20)
print("Message padded to a multiple of 20 bytes:", repr(msg.ascii()))

msg.stripPad()
print("De-padded message:", repr(msg.ascii()))

# more tests and examples
trials = 5
len_lower_bound = 0
len_upper_bound = 20

print("\nRunning %d trials with messages of lengths in [%d, %d]:" % (trials, len_lower_bound, len_upper_bound))
for trial in range(trials):
    msg = randMsg(len_lower_bound, len_upper_bound)
    print("\nOriginal message of length %d:\n" % len(msg), msg)
    msg.pad(16)
    print("Padded to a multiple of 16 bytes, length %d:\n" % len(msg), msg)
    msg.stripPad(16)
    print("Padding stripped, length %d:\n" % len(msg), msg)

print("\nNote behavior when message length is a multiple of the block size:")
msg = randMsg(16)
print("\nOriginal message of length %d:\n" % len(msg), msg)
msg.pad(16, extra=False)
print("Padded to a multiple of 16 bytes with flag 'extra=False', length %d:\n" % len(msg), msg)
msg.stripPad(16, strict=False)
print("Padding stripped with flag 'strict=False', length %d:\n" % len(msg), msg)
msg.pad(16, extra=True)
print("Padded to a multiple of 16 bytes with flag 'extra=True', length %d:\n" % len(msg), msg)
msg.stripPad(16, strict=True)
print("Padding stripped with flag 'strict=True', length %d:\n" % len(msg), msg)
