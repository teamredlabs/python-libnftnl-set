from typing import Dict, Tuple


_AttrSpec = Tuple[int, int, int]


class NetfilterElementHandle(object):
    """Wrapper for ``struct nftnl_set_elem *``."""

    flags: int
    key: str
    key_end: str
    verdict: int
    chain: str
    data: str
    timeout: int
    userdata: str
    objref: str

    def __init__(self) -> None: ...

    @property
    def expiration(self) -> int: ...


class NetfilterSetHandle(object):
    """Wrapper for ``struct nftnl_set *``."""

    table: str
    name: str
    flags: int
    key_type: int
    key_len: int
    data_type: int
    data_len: int
    family: int
    id: int
    policy: int
    desc_size: int
    timeout: int
    gc_interval: int
    userdata: str
    obj_type: int
    handle: int

    def __init__(self) -> None: ...
    def add(self, element: NetfilterElementHandle) -> None: ...


class NetfilterBatchHandle(object):
    """Wrapper for ``struct mnl_nlmsg_batch *``."""

    def __init__(self) -> None: ...
    def begin(self, bufsize: int) -> int: ...
    def set_put(self, set: NetfilterSetHandle, family: int, ack: bool) -> int: ...
    def set_del(self, set: NetfilterSetHandle, family: int, ack: bool) -> int: ...
    def elem_put(self, set: NetfilterSetHandle, family: int, ack: bool) -> int: ...
    def elem_del(self, set: NetfilterSetHandle, family: int, ack: bool) -> int: ...
    def end(self) -> int: ...
    def dump(self) -> str: ...


def element() -> NetfilterElementHandle: ...
def set() -> NetfilterSetHandle: ...
def batch() -> NetfilterBatchHandle: ...
def handle(buf: str, seq: int, pid: int) -> int: ...


# Message types
NLMSG_NOOP: int
NLMSG_ERROR: int
NLMSG_DONE: int
NLMSG_OVERRUN: int

# Message flags
NLM_F_REQUEST: int
NLM_F_MULTI: int
NLM_F_ACK: int
NLM_F_ECHO: int
NLM_F_DUMP_INTR: int
NLM_F_ROOT: int
NLM_F_MATCH: int
NLM_F_ATOMIC: int
NLM_F_DUMP: int
NLM_F_REPLACE: int
NLM_F_EXCL: int
NLM_F_CREATE: int
NLM_F_APPEND: int

# Set flags
NFT_SET_ANONYMOUS: int
NFT_SET_CONSTANT: int
NFT_SET_INTERVAL: int
NFT_SET_MAP: int
NFT_SET_TIMEOUT: int
NFT_SET_EVAL: int
NFT_SET_OBJECT: int

# Element flags
NFT_SET_ELEM_INTERVAL_END: int

# Protocol families
NFPROTO_IPV4: int
NFPROTO_IPV6: int
NFPROTO_BRIDGE: int
NFPROTO_ARP: int

# Socket constants
MNL_SOCKET_AUTOPID: int
MNL_SOCKET_BUFFER_SIZE: int

# Subsystem
NETLINK_NETFILTER: int

# Attribute specs
NFT_ATTR_SPECS_ELEM: Dict[str, _AttrSpec]
NFT_ATTR_SPECS_SET: Dict[str, _AttrSpec]
