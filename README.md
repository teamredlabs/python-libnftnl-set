# python-libnftnl-set

Python wrapper for libnftnl set/map operations.

# Usage

```python
import socket
import libnftnlset

nf_family = libnftnlset.NFPROTO_IPV4

nf_set = libnftnlset.set()
nf_set.table = 'table_name'
nf_set.name = 'set_name'

nf_elem = libnftnlset.element()
nf_elem.key = 'element_key'
nf_elem.data = 'element_data'

nf_set.add(nf_elem)

nf_batch = libnftnlset.batch()
nf_batch.begin()
nf_batch.elem_put(nf_set, nf_family, True)
nf_batch.end()

message = nf_batch.dump()

subsystem = libnftnlset.NETLINK_NETFILTER
sock = socket.socket(socket.AF_NETLINK,
                     socket.SOCK_RAW,
                     subsystem)

pid, groups = libnftnlset.MNL_SOCKET_AUTOPID, 0

sock.bind((pid, groups))
pid, groups = sock.getsockname()

count = sock.sendto(message, 0, (0, 0))

sock.recv(libnftnlset.MNL_SOCKET_BUFFER_SIZE)

```
