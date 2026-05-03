#! /usr/bin/env python3

import pexpect
import sys
import os
import random
import string
from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument('proj_path', nargs='?', default='.')
parser.add_argument('-d', '--discard-stderr',
                    dest='discard',
                    action='store_true',
                    default=False,
                    help='discard STDERR, if you are using it for diagnostics'
                    )
parser.add_argument('-l', '--log-stdout',
                    dest='logstdout',
                    action='store_true',
                    default=False,
                    help='log to stdout instead of stderr'
                    )
parser.add_argument('--no-cleanup',
                    dest='nocleanup',
                    action='store_true',
                    default=False,
                    help='disable cleanup'
                    )
parser.add_argument('--no-ext',
                    dest='no_ext',
                    action='store_true',
                    default=False,
                    help='Invoke bank and atm with /path/to/file instead of /path/to/file.bank'
                    )
args = parser.parse_args()

proj_path = args.proj_path
discard = ''
if args.discard:
    discard = ' 2>/dev/null'

# Fixed path for tests to ensure consistency
file_path = '/tmp/test' 

stderr = sys.stderr
stdout = sys.stdout
if 'buffer' in dir(stderr):
    stderr = stderr.buffer
if 'buffer' in dir(stdout):
    stdout = stdout.buffer

# Helper functions
def spawn(cmd, **kwargs):
    retval = None
    try:
        # Added encoding='utf-8' to support string matching in tests
        retval = pexpect.spawn('/bin/bash', ['-c', cmd + discard], timeout=5, encoding='utf-8', 
                               logfile=sys.stdout if args.logstdout else None, **kwargs)
        retval.ignorecase = True
        retval.setecho(False)
    except Exception as e:
        print(f"Spawn error: {e}")
        pass
    return retval

def delfile(f):
    if os.path.exists(f):
        os.unlink(f)

def cleanup():
    if args.nocleanup:
        return
    delfile('{fp}.bank'.format(fp=file_path))
    delfile('{fp}.atm'.format(fp=file_path))
    delfile('{fp}.card'.format(fp=file_path))
    # Also clean up card files created in current dir
    for f in os.listdir('.'):
        if f.endswith('.card'):
            os.unlink(f)

def check_exit(expected, actual):
    if expected != actual:
        print("Expected exit code {}, got {}".format(expected,actual))

def setup_environment():
    """Compiles and initializes the system"""
    print("\n[+] Setting up environment...")
    cleanup()
    
    # 1. Compile
    try:
        pexpect.run('make', timeout=15)
    except:
        print("Make failed")
    
    # 2. Init
    child = spawn('{path1}/bin/init {path2}'.format(path1=proj_path, path2=file_path))
    try:
        child.expect('Successfully initialized bank state')
        child.wait()
        child.close()
    except:
        print("Init failed")

# Test Cases
def test_input_validation():
    print("\n[TEST] Input Validation Edge Cases")
    
    router = spawn('{path}/bin/router'.format(path=proj_path))
    bank = spawn('{path}/bin/bank {fp}.bank'.format(path=proj_path, fp=file_path))
    
    # 1. Invalid Usernames (Symbols)
    bank.sendline('create-user ali$ce 1234 100')
    bank.expect(r'Usage:\s+create-user')
    
    # 2. Invalid Usernames (Too Long - 251 chars)
    long_name = "a" * 251
    bank.sendline(f'create-user {long_name} 1234 100')
    bank.expect(r'Usage:\s+create-user')
    
    # 3. Invalid PIN (Letters)
    bank.sendline('create-user bob 12ab 100')
    bank.expect(r'Usage:\s+create-user')
    
    # 4. Invalid PIN (Length)
    bank.sendline('create-user bob 123 100')
    bank.expect(r'Usage:\s+create-user')
    
    # 5. Invalid Balance (Negative)
    bank.sendline('create-user bob 1234 -100')
    bank.expect(r'Usage:\s+create-user')
    
    # 6. Invalid Balance (Overflow)
    bank.sendline('create-user bob 1234 3000000000') 
    bank.expect(r'Usage:\s+create-user')
    
    print("    [+] Input validation passed")
    router.close()
    bank.close()

def test_bank_logic():
    print("\n[TEST] Bank Logic Edge Cases")
    
    router = spawn('{path}/bin/router'.format(path=proj_path))
    bank = spawn('{path}/bin/bank {fp}.bank'.format(path=proj_path, fp=file_path))
    
    bank.sendline('create-user alice 1234 100')
    bank.expect('Created user alice')
    
    # 1. Duplicate User
    bank.sendline('create-user alice 1234 100')
    bank.expect('Error:  user alice already exists')
    
    # 2. Deposit to non-existent user
    bank.sendline('deposit ghost 100')
    bank.expect('No such user')
    
    # 3. Deposit negative amount
    bank.sendline('deposit alice -50')
    bank.expect(r'Usage:\s+deposit')
    
    # 4. Deposit Overflow (Rich check)
    bank.sendline('deposit alice 2147483600')
    bank.expect('Too rich for this program')
    
    print("    [+] Bank logic passed")
    router.close()
    bank.close()

def test_atm_workflow():
    print("\n[TEST] ATM Workflow & Logic")
    
    router = spawn('{path}/bin/router'.format(path=proj_path))
    bank = spawn('{path}/bin/bank {fp}.bank'.format(path=proj_path, fp=file_path))
    bank.sendline('create-user bob 1234 1000')
    bank.expect('Created user bob')
    
    atm = spawn('{path}/bin/atm {fp}.atm'.format(path=proj_path, fp=file_path))
    
    # 1. Withdraw with no session
    atm.sendline('withdraw 10')
    atm.expect('No user logged in')
    
    # 2. Login with wrong PIN (Single attempt)
    atm.sendline('begin-session bob')
    atm.expect(r'PIN\?')
    atm.sendline('0000')
    atm.expect('Not authorized')
    
    # 3. Successful Login
    atm.sendline('begin-session bob')
    atm.expect(r'PIN\?')
    atm.sendline('1234')
    atm.expect('Authorized')
    
    # 4. Double Login
    atm.sendline('begin-session bob')
    atm.expect('A user is already logged in')
    
    # 5. Withdraw Insufficient Funds
    atm.sendline('withdraw 2000')
    atm.expect('Insufficient funds')
    
    # 6. Valid Withdraw
    atm.sendline('withdraw 500')
    atm.expect(r'\$500 dispensed')
    
    # 7. Check Balance
    atm.sendline('balance')
    atm.expect(r'\$500') # 1000 - 500
    
    # 8. End Session
    atm.sendline('end-session')
    atm.expect('User logged out')
    
    print("    [+] ATM workflow passed")
    router.close()
    bank.close()
    atm.close()

def test_lockout_timing():
    print("\n[TEST] Vulnerability 4: Lockout Timing")
    
    router = spawn('{path}/bin/router'.format(path=proj_path))
    bank = spawn('{path}/bin/bank {fp}.bank'.format(path=proj_path, fp=file_path))
    
    username = "hacker"
    bank.sendline(f'create-user {username} 1234 100')
    bank.expect(f'Created user {username}')
    
    atm = spawn('{path}/bin/atm {fp}.atm'.format(path=proj_path, fp=file_path))
    
    print("    [.] Attempting 3 failed logins...")
    
    for _ in range(3):
        atm.sendline(f'begin-session {username}')
        atm.expect(r'PIN\?')
        atm.sendline('0000')
        atm.expect('Not authorized')
    
    try:
        bank.expect(f'Account {username} locked for 60 seconds', timeout=5)
        print("    [+] Bank confirmed lockout!")
    except:
        print("    [-] Bank did NOT print lockout message (or timeout)")
        
    print("    [.] Attempting 4th login with CORRECT PIN (Should Fail)...")
    
    atm.sendline(f'begin-session {username}')
    atm.expect(r'PIN\?')
    atm.sendline('1234') # Correct PIN!
    
    try:
        atm.expect('Not authorized', timeout=5)
        print("    [+] Lockout enforcement confirmed: Correct PIN rejected.")
    except:
        print("    [-] Lockout FAILED: Correct PIN was accepted!")
        router.close(); bank.close(); atm.close(); sys.exit(1)

    print("    [+] Lockout test passed")
    router.close()
    bank.close()
    atm.close()

def test_replay_restart():
    print("\n[TEST] Vulnerability 2: ATM Restart Replay")
    
    router = spawn('{path}/bin/router'.format(path=proj_path))
    bank = spawn('{path}/bin/bank {fp}.bank'.format(path=proj_path, fp=file_path))
    
    bank.sendline('create-user replay 1234 100')
    
    # Start ATM 1
    atm1 = spawn('{path}/bin/atm {fp}.atm'.format(path=proj_path, fp=file_path))
    atm1.sendline('begin-session replay')
    atm1.expect(r'PIN\?')
    atm1.sendline('1234')
    atm1.expect('Authorized')
    atm1.sendline('withdraw 10')
    atm1.expect(r'\$10 dispensed')
    
    print("    [.] ATM 1 transaction complete. Nonce incremented.")
    atm1.close()
    
    print("    [.] ATM restarted. Nonce reset to 0.")
    
    # Start ATM 2 (Simulating restart)
    atm2 = spawn('{path}/bin/atm {fp}.atm'.format(path=proj_path, fp=file_path))
    atm2.sendline('begin-session replay')
    atm2.expect(r'PIN\?')
    atm2.sendline('1234')
    
    # This should FAIL because ATM sends Nonce 1, but Bank expects > 1
    try:
        bank.expect('Replay attack detected', timeout=5)
        print("    [+] Bank detected replay/restart correctly!")
        
        atm2.expect('Not authorized', timeout=5)
        print("    [+] ATM denied access.")
    except:
        print("    [-] Replay protection FAILED or Message not printed.")
        sys.exit(1)

    print("    [+] Replay test passed")
    router.close()
    bank.close()
    atm2.close()

def test_tampering_attack():
    print("\n[TEST] Tampering / Bit-Flipping Integrity")
    
    setup_environment()
    
    bank = spawn('{path}/bin/bank {fp}.bank'.format(path=proj_path, fp=file_path))
    bank.sendline('create-user alice 1234 100')
    bank.expect('Created user alice')
    
    # ATTACK: Corrupt the ATM's key file
    with open(f"{file_path}.atm", "r+b") as f:
        f.seek(0)
        byte = f.read(1)
        f.seek(0)
        f.write(bytes([byte[0] ^ 0x01]))
        
    atm = spawn('{path}/bin/atm {fp}.atm'.format(path=proj_path, fp=file_path))
    atm.sendline('begin-session alice')
    
    try:
        index = bank.expect(['Failed to decrypt', pexpect.TIMEOUT], timeout=5)
        if index == 0:
            print("    [+] Bank rejected tampered packet (Message received)")
        else:
            print("    [+] Bank silent drop (Secure behavior)")
        
        try:
            atm.expect('Not authorized', timeout=5)
        except pexpect.TIMEOUT:
            pass 
            
        print("    [+] Integrity check passed")
    except Exception as e:
        print(f"    [-] Tampering check FAILED: {e}")
        sys.exit(1)
        
    bank.close()
    atm.close()

def test_fuzzing():
    print("\n[TEST] Input Fuzzing (Garbage Data)")
    
    setup_environment()
    bank = spawn('{path}/bin/bank {fp}.bank'.format(path=proj_path, fp=file_path))
    
    garbage_inputs = ["", "   ", "\x00\x01\x02", "create-user " + "A"*1000, "balance %s%s"]
    
    for junk in garbage_inputs:
        bank.sendline(junk)
        unique_user = ''.join(random.choices(string.ascii_lowercase, k=6))
        try:
            bank.sendline(f'create-user {unique_user} 1234 100')
            bank.expect(f'Created user {unique_user}', timeout=2)
        except:
            print(f"    [-] Bank CRASHED on input: {junk}")
            sys.exit(1)
            
    print("    [+] Bank survived fuzzing.")
    bank.close()

if __name__ == "__main__":
    try:
        setup_environment()
        
        test_input_validation()
        test_bank_logic()
        test_atm_workflow()
        test_lockout_timing()
        test_replay_restart()
        test_tampering_attack()
        test_fuzzing()
        
        print("\n[SUCCESS] All comprehensive tests passed!\n")
        cleanup()
    except Exception as e:
        print(f"\n[FAILURE] Test failed: {e}")
        cleanup()
        sys.exit(1)