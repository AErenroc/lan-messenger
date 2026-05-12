"""
LAN Messenger - - - Tests!

TODO: make sure all tests work then move to adding encryption. - then add more tests
"""

import sys
import queue
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from server.server import Server
from server.database import Database
from client.connection import Connection
from shared.protocol import MSG_OK, MSG_ERROR, MSG_DELIVER, MSG_USER_LIST, MSG_NOTIFY

TEST_PORT = 54399
TEST_DB   = Path(__file__).parent / "server" / "test_lanmsg.db"

results = []
errors  = []

def log(msg):
    print(f"  {msg}")


# Helpers  --------------------------------------------------------------------------------------------------
def make_conn() -> Connection:
    c = Connection("127.0.0.1", TEST_PORT)
    c.connect(timeout=3.0)
    return c


def wait_for(conn: Connection, msg_type: str, timeout: float = 2.0):
    """Block until a packet of the given type arrives."""
    q: queue.Queue = queue.Queue()

    def cb(pkt):
        q.put(pkt)

    conn.on(msg_type, cb)
    try:
        return q.get(timeout=timeout)
    except queue.Empty:
        return None



# Test runner --------------------------------------------------------------------------------------------------
def assert_ok(label, pkt):
    if pkt and pkt.get("type") == MSG_OK:
        log(f"o {label}")
        results.append(("PASS", label))
    else:
        msg = pkt.get("info", "no packet") if pkt else "timeout / no packet"
        log(f"x {label}: {msg}")
        results.append(("FAIL", label))
        errors.append(label)


def assert_error(label, pkt):
    if pkt and pkt.get("type") == MSG_ERROR:
        log(f"o {label}")
        results.append(("PASS", label))
    else:
        log(f"x {label}: expected ERROR, got {pkt}")
        results.append(("FAIL", label))
        errors.append(label)



# Main --------------------------------------------------------------------------------------------------
def run_tests():
    print("\n" + "="*55)
    print("  LAN Messenger <><><> Tests")
    print("="*50)

    # Boot server -------------------------------------------------
    if TEST_DB.exists():
        TEST_DB.unlink()

    server = Server("127.0.0.1", TEST_PORT)
    server.db = Database(TEST_DB)  # isolated DB
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    time.sleep(0.3)


    # 1. Registration <> <> <> <> <> <> <> <> <> <> <> <> <> <> <> <>
    print("\n[1] Registration")
    c = make_conn()
    c.register("alice")
    assert_ok("register alice", wait_for(c, MSG_OK))
    c.register("alice")
    assert_error("re-register alice (should fail)", wait_for(c, MSG_ERROR))
    c.register("bob")
    assert_ok("register bob", wait_for(c, MSG_OK))
    c.register("carol")
    assert_ok("register carol", wait_for(c, MSG_OK))
    c.disconnect()

  
    # 2. Login / logout <> <> <> <> <> <> <> <> <> <> <> <> <> <> <> <>
    print("\n[2] Login / logout")
    alice = make_conn()
    alice.login("alice")
    assert_ok("alice login", wait_for(alice, MSG_OK))
    alice.login("nobody")
    assert_error("login unknown user", wait_for(alice, MSG_ERROR))
    alice.logout()
    assert_ok("alice logout", wait_for(alice, MSG_OK))


    # 3. Online direct message <> <> <> <> <> <> <> <> <> <> <> <> <> <> <> <>
    print("\n[3] Online direct message")
    alice = make_conn()
    alice.login("alice")
    wait_for(alice, MSG_OK)

    bob = make_conn()
    bob_live = []
    bob.on(MSG_DELIVER, lambda p: bob_live.append(p))
    bob.login("bob")
    wait_for(bob, MSG_OK)

    # alice --> bob (bob is online, should deliver immediately)
    alice.send_message("bob", "Hello Bob, are you there?")
    assert_ok("alice send to online bob", wait_for(alice, MSG_OK))
    time.sleep(0.3)
    delivered = bob_live[-1] if bob_live else None
    if delivered and delivered.get("body") == "Hello Bob, are you there?":
        log("✓ bob received message in real-time")
        results.append(("PASS", "bob real-time delivery"))
    else:
        log(f"✗ bob real-time delivery: {delivered}")
        results.append(("FAIL", "bob real-time delivery"))
        errors.append("bob real-time delivery")

  
  
    # 4. Store-and-forward (offline delivery)  <> <> <> <> <> <> <> <> <> <> <> <>
    print("\n[4] Store-and-forward (offline delivery)")
    bob.disconnect()
    time.sleep(1.0)  # wait for server recv thread to detect close and remove session

    # alice sends to bob while he is definitely offline
    alice.send_message("bob", "Are you awake? (stored offline)")
    assert_ok("send to offline bob (stored)", wait_for(alice, MSG_OK))

    # bob comes back online – pending messages should arrive on login
    bob2 = make_conn()
    delivered_msgs = []
    bob2.on(MSG_DELIVER, lambda p: delivered_msgs.append(p))
    bob2.login("bob")
    time.sleep(0.6)  # give server time to push pending

    if any(m.get("body") == "Are you awake? (stored offline)" for m in delivered_msgs):
        log("✓ bob received stored message on login")
        results.append(("PASS", "store-and-forward delivery"))
    else:
        log(f"✗ store-and-forward: delivered_msgs={delivered_msgs}")
        results.append(("FAIL", "store-and-forward delivery"))
        errors.append("store-and-forward delivery")


    # 5. Broadcast  <> <> <> <> <> <> <> <> <> <> <> <> <> <> <> <>
    print("\n[5] Broadcast")
    carol = make_conn()
    carol.login("carol")
    wait_for(carol, MSG_OK)

    carol_received = []
    carol.on(MSG_DELIVER, lambda p: carol_received.append(p))

    alice.broadcast("Hello everyone on the LAN!")
    assert_ok("alice broadcast", wait_for(alice, MSG_OK))
    time.sleep(0.3)

    if any(m.get("body") == "Hello everyone on the LAN!" for m in carol_received):
        log("✓ carol received broadcast")
        results.append(("PASS", "broadcast delivery"))
    else:
        log(f"✗ broadcast delivery: {carol_received}")
        results.append(("FAIL", "broadcast delivery"))
        errors.append("broadcast delivery")


    # 6. /fetch (manual pull)  <> <> <> <> <> <> <> <> <> <> <> <> <> <> <> <>
    print("\n[6] Manual fetch")
    carol.logout()
    wait_for(carol, MSG_OK)
    carol.disconnect()
    time.sleep(0.1)

    # send something to carol while she's offline
    alice.send_message("carol", "Hey Carol, call me back.")
    wait_for(alice, MSG_OK)

    # carol logs back in on a new connection and fetches
    carol2 = make_conn()
    fetched = []
    carol2.on(MSG_DELIVER, lambda p: fetched.append(p))
    carol2.login("carol")
    time.sleep(0.4)  # auto-delivered on login

    if any(m.get("body") == "Hey Carol, call me back." for m in fetched):
        log("✓ carol fetched stored message")
        results.append(("PASS", "fetch pending on login"))
    else:
        log(f"✗ fetch pending: {fetched}")
        results.append(("FAIL", "fetch pending on login"))
        errors.append("fetch pending on login")


    # 7. User list  <> <> <> <> <> <> <> <> <> <> <> <> <> <> <> <>
    print("\n[7] User list")
    user_list_pkt = [None]
    alice.on(MSG_USER_LIST, lambda p: user_list_pkt.__setitem__(0, p))
    alice.list_users()
    time.sleep(0.4)
    if user_list_pkt[0]:
        users = {u["username"].lower() for u in user_list_pkt[0].get("users", [])}
        if {"alice", "bob", "carol"} <= users:
            log("✓ user list contains alice, bob, carol")
            results.append(("PASS", "user list"))
        else:
            log(f"✗ user list missing users: {users}")
            results.append(("FAIL", "user list"))
            errors.append("user list")
    else:
        log("✗ user list: no response")
        results.append(("FAIL", "user list"))
        errors.append("user list")

    
    # 8. Error: send to unknown user  <> <> <> <> <> <> <> <> <> <> <> <> <> <> <> <>
    print("\n[8] Error handling")
    alice.send_message("nobody_real", "ghost mail")
    assert_error("send to nonexistent user", wait_for(alice, MSG_ERROR))

    alice.send_message("alice", "self mail")
    assert_error("send to self (should fail)", wait_for(alice, MSG_ERROR))


    # Cleanup ------------------------------------------------
    alice.disconnect()
    bob2.disconnect()
    carol2.disconnect()
    if TEST_DB.exists():
        TEST_DB.unlink()


    # Summary -----------------------------------------------
    print("\n" + "="*55)
    passed = sum(1 for r, _ in results if r == "PASS")
    total  = len(results)
    print(f"  Results: {passed}/{total} passed")
    if errors:
        print(f"  Failed:  {', '.join(errors)}")
    print("="*55 + "\n")
    return len(errors) == 0


if __name__ == "__main__":
    ok = run_tests()
    sys.exit(0 if ok else 1)
