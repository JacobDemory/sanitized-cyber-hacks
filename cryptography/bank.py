import sys
from itertools import permutations

BLOCK_SIZE = 16

def read_file_as_blocks(filename):
	blocks = []
	with open(filename, 'rb') as f:
		while True:
			chunk = f.read(BLOCK_SIZE)
			if not chunk:
				break
			blocks.append(chunk)
	return blocks

def write_blocks_to_file(filename, blocks):
	with open(filename, 'wb') as f:
		for b in blocks:
			f.write(b)

def parse_session(blocks):
	if (not blocks) or (len(blocks) < 2):
		return []
	
	first_command_block = blocks[1]
	unique_blocks = list(set(blocks))
	other_commands = [b for b in unique_blocks if b != first_command_block]

	for p in permutations(other_commands, 2):
		current_trio = [first_command_block, p[0], p[1]]
		for assigned_commands in permutations(current_trio):
			bal_cmd = assigned_commands[0]
			trans_cmd = assigned_commands[1]
			inv_cmd = assigned_commands[2]

			current_map = {
				bal_cmd:  {"type": "BALANCE", "length": 2},
				trans_cmd: {"type": "TRANSFER", "length": 5},
				inv_cmd:   {"type": "INVOICE", "length": 4}
			}

			cursor = 0
			temp_messages = []
			valid = True
			
			while cursor < len(blocks):
				if cursor + 1 >= len(blocks):
					valid = False
					break
				
				cmd_block = blocks[cursor + 1]
				
				if cmd_block not in current_map:
					valid = False
					break
				
				info = current_map[cmd_block]
				length = info['length']
				m_type = info['type']
				
				if cursor + length > len(blocks):
					valid = False
					break
				
				temp_messages.append({
					"type": m_type,
					"data": blocks[cursor : cursor + length]
				})
				
				cursor += length
				
			if valid and cursor == len(blocks):
				return temp_messages

	sys.stderr.write("Error: Parser could not match blocks to protocol.\n")
	return []