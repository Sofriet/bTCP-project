# TODO

This repo only has our own code (`btcp/client_socket.py` and `btcp/server_socket.py`).
The rest of the course template and the test framework are not in here yet, so
the code can't run on its own until they are added back.

## 1. Add the template files

- [ ] `btcp/__init__.py`
- [ ] `btcp/btcp_socket.py`. This has to be **our completed version**, not the
      blank template one, because the sockets call these methods on it:
  - `unpack_segment_header(header)` returns
    `(seqnum, acknum, flags, window, length, checksum)`
  - `verify_checksum(segment)` returns `True` when the checksum is correct
  - `make_segment(data, seqnum, ack_set, acknum)` returns a full
    `SEGMENT_SIZE` segment (header with checksum, then `data` padded to
    `PAYLOAD_SIZE`). It must accept empty `data` for pure ACKs.
  - plus `in_cksum` / `build_segment_header` (used by the above) and the
    `BTCPStates` enum. The ACK flag is bit 1 (`0b010`), as in the template's
    `build_segment_header`.
- [ ] `btcp/lossy_layer.py` (unchanged from the template)
- [ ] `btcp/constants.py` (template version). The sockets use `CLIENT_IP`,
      `CLIENT_PORT`, `SERVER_IP`, `SERVER_PORT`, `HEADER_SIZE` and
      `PAYLOAD_SIZE`. The old `TIMEOUT` constant is no longer needed: the client
      now uses the `timeout` (ms) given to the socket constructor.
- [ ] `app_client.py` and `app_server.py` in the repo root

> When copying the template's `btcp/` folder in, **don't overwrite**
> `btcp/client_socket.py` and `btcp/server_socket.py`.

## 2. Add the tests

- [ ] `testframework.py` in the repo root. The README says the test cases are
      private for the assignment, so check that you're allowed to publish it.
      If not, keep it local and add it to `.gitignore`.
- [ ] Re-run all tests on the fixed code and update the test results in
      `README.md` (the "passes 1_1, 2_1, 3_1" line is from the old code).
