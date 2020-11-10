# python-libnftnl-set

Python wrapper for libnftnl set/map operations.

# Usage

To add an element to a set, refer to the following snippet (note the call to `elem_put`):

```python
import socket
import libnftnlset

# Prepare family

nf_family = libnftnlset.NFPROTO_IPV4

# Prepare set

nf_set = libnftnlset.set()
nf_set.table = 'table_name'
nf_set.name = 'set_name'

# Prepare element

nf_elem = libnftnlset.element()

# It's up to you to figure out how this is serialized depending on your use
# case. Personally, what I did was intercept calls to nftnl_set_elem_set in the
# libnftnl library and printed out the parameters in hex format.

# Most of the serialization logic is found on the source code of the nftables
# command line tool. I didn't write a Python wrapper for it because it's too
# much of a hassle. If you're brave enough, maybe you could. That would be
# terrific.

nf_elem.key = 'element_key_bytes'
nf_elem.data = 'element_data_bytes'

# Add element to set

nf_set.add(nf_elem)

# Construct the request

nf_batch = libnftnlset.batch()
nf_batch.begin()
nf_batch.elem_put(nf_set, nf_family, True)
nf_batch.end()

# Serialize the request

request = nf_batch.dump()

# Prepare netlink socket

subsystem = libnftnlset.NETLINK_NETFILTER
sock = socket.socket(socket.AF_NETLINK,
                     socket.SOCK_RAW,
                     subsystem)
pid, groups = libnftnlset.MNL_SOCKET_AUTOPID, 0
sock.bind((pid, groups))
pid, groups = sock.getsockname()

# Send the request

sent = sock.sendto(request, 0, (0, 0))

# Perform receive loop

response = sock.recv(libnftnlset.MNL_SOCKET_BUFFER_SIZE)
status = len(response)
while 0 < status:
    status = libnftnlset.handle(response, 0, pid)
    if 0 < status:
        response = sock.recv(libnftnlset.MNL_SOCKET_BUFFER_SIZE)
        status = len(response)
        continue
    break

success = status >= 0
print 'success', success

```

To remove an element from a set, refer to the following snippet (note the call to `elem_del`):

```python
import socket
import libnftnlset

# Prepare family

nf_family = libnftnlset.NFPROTO_IPV4

# Prepare set

nf_set = libnftnlset.set()
nf_set.table = 'table_name'
nf_set.name = 'set_name'

# Prepare element

nf_elem = libnftnlset.element()

# It's up to you to figure out how this is serialized depending on your use
# case. Personally, what I did was intercept calls to nftnl_set_elem_set in the
# libnftnl library and printed out the parameters in hex format.

# Most of the serialization logic is found on the source code of the nftables
# command line tool. I didn't write a Python wrapper for it because it's too
# much of a hassle. If you're brave enough, maybe you could. That would be
# terrific.

nf_elem.key = 'element_key_bytes'
nf_elem.data = 'element_data_bytes'

# Add element to set

nf_set.add(nf_elem)

# Construct the request

nf_batch = libnftnlset.batch()
nf_batch.begin()
nf_batch.elem_del(nf_set, nf_family, True)
nf_batch.end()

# Serialize the request

request = nf_batch.dump()

# Prepare netlink socket

subsystem = libnftnlset.NETLINK_NETFILTER
sock = socket.socket(socket.AF_NETLINK,
                     socket.SOCK_RAW,
                     subsystem)
pid, groups = libnftnlset.MNL_SOCKET_AUTOPID, 0
sock.bind((pid, groups))
pid, groups = sock.getsockname()

# Send the request

sent = sock.sendto(request, 0, (0, 0))

# Perform receive loop

response = sock.recv(libnftnlset.MNL_SOCKET_BUFFER_SIZE)
status = len(response)
while 0 < status:
    status = libnftnlset.handle(response, 0, pid)
    if 0 < status:
        response = sock.recv(libnftnlset.MNL_SOCKET_BUFFER_SIZE)
        status = len(response)
        continue
    break

success = status >= 0
print 'success', success

```
