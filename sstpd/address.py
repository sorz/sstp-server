import ipaddress


class IPPool(object):

    def __init__(self, network):
        if isinstance(network, str):
            network = network.decode()
        self._pool = []
        self._capacity = None
        self._network = ipaddress.ip_network(network)
        self._hosts = self._network.hosts()


    def _next_host(self):
        for host in self._hosts:
            if host in self._pool:
                continue
            return host


    def register(self, address):
        if isinstance(address, str):
            address = address.decode()
        addr = ipaddress.ip_address(address)
        if addr in self._pool:
            raise RegisteredException()
        self._pool.append(addr)


    def apply(self):
        """Return a available IP address and register it.
        Return None if the pool is full.
        """
        if self._capacity is not None and len(self._pool) == self._capacity:
            return
        addr = self._next_host()
        if addr is None:
            self.reset()
            addr = self._next_host()
        if addr is None:
            if self._capacity is None:
                self._capacity = len(self._pool)
        else:
            self._pool.append(addr)
        return addr


    def unregister(self, address):
        if isinstance(address, str):
            address = address.decode()
        addr = ipaddress.ip_address(address)
        try:
            self._pool.remove(addr)
        except ValueError:
            pass


    def reset(self):
        self._hosts = self._network.hosts()


class RegisteredException(Exception):
    pass


