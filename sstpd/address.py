import ipaddress


class IPPool:
    def __init__(self, network, range=None):
        self._pool = []
        self._capacity = None
        self._network = ipaddress.ip_network(network)
        self._first = self._network.network_address + 1
        self._last = self._network.broadcast_address - 1
        if range:
            r_err = ValueError("Range " + range + " not in network " + network)
            first, last = range.split("-")
            if self._network.overlaps(ipaddress.ip_network(first)):
                self._first = ipaddress.ip_address(first)
            else:
                raise r_err
            if last:
                try:
                    if self._network.overlaps(ipaddress.ip_network(last)):
                        self._last = ipaddress.ip_address(last)
                    else:
                        raise r_err
                except ValueError as err:
                    if err != r_err:
                        self._last = self._network.network_address + int(last)
        self.reset()

    def _next_host(self):
        for host in self._hosts:
            if host in self._pool:
                continue
            return host

    def register(self, address):
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
        addr = ipaddress.ip_address(address)
        try:
            self._pool.remove(addr)
        except ValueError:
            pass

    def reset(self):
        self._hosts = filter(
            lambda host: host >= self._first and host <= self._last,
            self._network.hosts(),
        )


class RegisteredException(Exception):
    pass
