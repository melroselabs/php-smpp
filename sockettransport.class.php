<?php

/**
 * TCP Socket Transport for use with multiple protocols.
 * Supports connection pools and IPv6, providing public methods to simplify usage.
 * Primarily designed for long-running connections, without support for socket reuse or IP blacklisting.
 * Assumes a blocking/synchronous architecture, blocking during read/write operations while enforcing timeouts.
 * 
 * Licensed under the MIT License.
 * Updated for PHP 8 compatibility and refactored for improved reliability and readability.
 * Based on original code by OnlineCity / hd@onlinecity.dk.
 */
class SocketTransport
{
    protected $socket;
    protected array $hosts = [];
    protected bool $persist;
    protected $debugHandler;
    public bool $debug;

    protected static int $defaultSendTimeout = 100;
    protected static int $defaultRecvTimeout = 750;
    public static bool $defaultDebug = false;

    public static bool $forceIpv6 = false;
    public static bool $forceIpv4 = false;
    public static bool $randomHost = false;

    /**
     * Construct a new socket for this transport to use.
     *
     * @param array $hosts List of hosts to try.
     * @param array|int $ports List of ports to try, or a single common port.
     * @param bool $persist Use persistent sockets.
     * @param callable|null $debugHandler Callback for debug info.
     */
    public function __construct(array $hosts, int|array $ports, bool $persist = false, ?callable $debugHandler = null)
    {
        $this->debug = self::$defaultDebug;
        $this->debugHandler = $debugHandler ?: fn($message) => error_log($message);

        $hostPortPairs = [];
        foreach ($hosts as $key => $host) {
            $hostPortPairs[] = [$host, is_array($ports) ? $ports[$key] : $ports];
        }
        if (self::$randomHost) shuffle($hostPortPairs);
        $this->resolveHosts($hostPortPairs);

        $this->persist = $persist;
    }

    /**
     * Resolve hostnames into IPs, sorted into IPv4 or IPv6 groups.
     *
     * @param array $hosts
     * @throws InvalidArgumentException if no valid hosts found.
     */
    protected function resolveHosts(array $hosts): void
    {
        $totalIps = 0;
        foreach ($hosts as [$hostname, $port]) {
            $ip4s = [];
            $ip6s = [];
            if (filter_var($hostname, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $ip4s[] = $hostname;
            } elseif (filter_var($hostname, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $ip6s[] = $hostname;
            } else {
                $ip6s = self::$forceIpv4 ? [] : $this->resolveDns($hostname, DNS_AAAA);
                $ip4s = self::$forceIpv6 ? [] : $this->resolveDns($hostname, DNS_A);
            }

            if ($this->debug) {
                $totalIps += count($ip4s) + count($ip6s);
            }

            if (empty($ip4s) && empty($ip6s)) {
                continue;
            }

            $this->hosts[] = [$hostname, $port, $ip6s, $ip4s];
        }

        if ($this->debug) {
            ($this->debugHandler)("Built connection pool of " . count($this->hosts) . " host(s) with $totalIps IP(s) in total");
        }
        if (empty($this->hosts)) {
            throw new InvalidArgumentException('No valid hosts found');
        }
    }

    private function resolveDns(string $hostname, int $type): array
    {
        $ips = [];
        $records = dns_get_record($hostname, $type);
        if ($records === false && $this->debug) {
            ($this->debugHandler)("DNS lookup for records for $hostname failed");
        } elseif ($records) {
            foreach ($records as $record) {
                $ipField = ($type === DNS_AAAA) ? 'ipv6' : 'ip';
                if (isset($record[$ipField]) && $record[$ipField]) {
                    $ips[] = $record[$ipField];
                }
            }
        }
        return $ips;
    }

    public function getSocket(): mixed
    {
        return $this->socket;
    }

    public function getSocketOption(int $option, int $level = SOL_SOCKET): mixed
    {
        return socket_get_option($this->socket, $level, $option);
    }

    public function setSocketOption(int $option, mixed $value, int $level = SOL_SOCKET): bool
    {
        return socket_set_option($this->socket, $level, $option, $value);
    }

    public function setSendTimeout(int $timeout): bool
    {
        if (!$this->isOpen()) {
            self::$defaultSendTimeout = $timeout;
            return true;
        }
        return socket_set_option($this->socket, SOL_SOCKET, SO_SNDTIMEO, $this->millisecToSolArray($timeout));
    }

    public function setRecvTimeout(int $timeout): bool
    {
        if (!$this->isOpen()) {
            self::$defaultRecvTimeout = $timeout;
            return true;
        }
        return socket_set_option($this->socket, SOL_SOCKET, SO_RCVTIMEO, $this->millisecToSolArray($timeout));
    }

	public function isOpen(): bool
	{
	    // Check if socket is null or has errors
	    if ($this->socket === null || socket_last_error($this->socket) !== 0) {
	        return false;
	    }
	
	    // Prepare read, write, and exception arrays
	    $r = [$this->socket];
	    $w = [];
	    $e = [$this->socket];
	
	    // Perform the socket select check with a timeout of 0 to avoid blocking
	    $res = socket_select($r, $w, $e, 0);
	
	    // Check if socket_select returned an error
	    if ($res === false) {
	        throw new SocketTransportException(
	            'Could not examine socket; ' . socket_strerror(socket_last_error($this->socket)),
	            socket_last_error($this->socket)
	        );
	    }
	
	    // If there is an exception on our socket, it is likely dead
	    if (!empty($e)) {
	        return false;
	    }
	
	    // If no issues, the socket is considered open
	    return true;
	}

    private function millisecToSolArray(int $millisec): array
    {
        $usec = $millisec * 1000;
        return ['sec' => floor($usec / 1000000), 'usec' => $usec % 1000000];
    }

    public function open(): void
    {
        $socket6 = $socket4 = null;

        if (!self::$forceIpv4) {
            $socket6 = @socket_create(AF_INET6, SOCK_STREAM, SOL_TCP);
            if ($socket6 === false) {
                throw new SocketTransportException('IPv6 socket creation error: ' . socket_strerror(socket_last_error()));
            }
            $this->applySocketOptions($socket6);
        }

        if (!self::$forceIpv6) {
            $socket4 = @socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
            if ($socket4 === false) {
                throw new SocketTransportException('IPv4 socket creation error: ' . socket_strerror(socket_last_error()));
            }
            $this->applySocketOptions($socket4);
        }

        foreach ($this->hosts as [$hostname, $port, $ip6s, $ip4s]) {
        	echo $hostname . PHP_EOL;
            if ($this->attemptConnection($ip4s, $socket4, $port)) return;
        }
        throw new SocketTransportException('Unable to connect to any specified hosts');
    }

    private function applySocketOptions($socket): void
    {
        socket_set_option($socket, SOL_SOCKET, SO_SNDTIMEO, $this->millisecToSolArray(self::$defaultSendTimeout));
        socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, $this->millisecToSolArray(self::$defaultRecvTimeout));
    }

    private function attemptConnection(array $ips, $socket, int $port): bool
    {
        foreach ($ips as $ip) {
            if ($this->debug) {
                ($this->debugHandler)("Connecting to $ip:$port...");
            }
            if (@socket_connect($socket, $ip, $port)) {
                if ($this->debug) {
                    ($this->debugHandler)("Connected to $ip:$port!");
                }
                $this->socket = $socket;
                return true;
            }
        }
        return false;
    }

    public function close(): void
    {
        if (is_resource($this->socket)) {
            socket_set_option($this->socket, SOL_SOCKET, SO_LINGER, ['l_onoff' => 1, 'l_linger' => 1]);
            socket_close($this->socket);
        }
    }

    /**
     * Read up to $length bytes from the socket.
     * Returns false on timeout or end-of-file.
     *
     * @param int $length
     * @return string|false
     * @throws SocketTransportException
     */
    public function read(int $length)
    {
        $data = socket_read($this->socket, $length, PHP_BINARY_READ);
        if ($data === false) {
            $error = socket_last_error($this->socket);
            if ($error === SOCKET_EAGAIN || $error === SOCKET_EWOULDBLOCK) return false;
            throw new SocketTransportException('Could not read ' . $length . ' bytes from socket; ' . socket_strerror($error), $error);
        }
        return $data === '' ? false : $data;
    }

    /**
     * Read all bytes and block until they are read.
     * Returns the exact number of bytes requested, or throws a timeout exception.
     *
     * @param int $length
     * @return string
     * @throws SocketTransportException
     */
    public function readAll(int $length): string
    {
        $data = '';
        $received = 0;
        $timeout = socket_get_option($this->socket, SOL_SOCKET, SO_RCVTIMEO);

        while ($received < $length) {
            $buffer = '';
            $bytes = socket_recv($this->socket, $buffer, $length - $received, MSG_DONTWAIT);
            if ($bytes === false) {
                throw new SocketTransportException('Could not read ' . $length . ' bytes from socket; ' . socket_strerror(socket_last_error($this->socket)), socket_last_error($this->socket));
            }
            $data .= $buffer;
            $received += $bytes;

            if ($received === $length) return $data;

            $r = [$this->socket];
            $w = $e = null;
            $select = socket_select($r, $w, $e, $timeout['sec'], $timeout['usec']);
            if ($select === false) {
                throw new SocketTransportException('Socket select error: ' . socket_strerror(socket_last_error($this->socket)), socket_last_error($this->socket));
            }
            if ($select === 0) {
                throw new SocketTransportException('Timed out waiting for data on socket');
            }
        }

        return $data;
    }

    /**
     * Write (all) data to the socket.
     * Throws exception on timeout or if unable to write.
     *
     * @param string $buffer
     * @param int $length
     * @throws SocketTransportException
     */
    public function write(string $buffer, int $length): void
    {
        $remaining = $length;
        $timeout = socket_get_option($this->socket, SOL_SOCKET, SO_SNDTIMEO);

        while ($remaining > 0) {
            $written = socket_write($this->socket, $buffer, $remaining);
            if ($written === false) {
                throw new SocketTransportException('Could not write ' . $length . ' bytes to socket; ' . socket_strerror(socket_last_error($this->socket)), socket_last_error($this->socket));
            }
            $remaining -= $written;
            if ($remaining === 0) return;

            $buffer = substr($buffer, $written);

            $r = $w = [$this->socket];
            $e = null;
            $select = socket_select($r, $w, $e, $timeout['sec'], $timeout['usec']);
            if ($select === false) {
                throw new SocketTransportException('Socket select error: ' . socket_strerror(socket_last_error($this->socket)), socket_last_error($this->socket));
            }
            if ($select === 0) {
                throw new SocketTransportException('Timed out waiting to write data on socket');
            }
        }
    }
    
}

class SocketTransportException extends RuntimeException {}
