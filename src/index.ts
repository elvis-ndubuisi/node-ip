// const ip = exports;
// const {Buffer} = require('buffer');
// const os = require('os');

// ip.toBuffer = function (ip, buff, offset) {
// 	offset = ~~offset;

// 	let result;

// 	if (this.isV4Format(ip)) {
// 		result = buff || Buffer.alloc(offset + 4);
// 		ip.split(/\./g).map((byte) => {
// 			result[offset++] = parseInt(byte, 10) & 0xff;
// 		});
// 	} else if (this.isV6Format(ip)) {
// 		const sections = ip.split(':', 8);

// 		let i;
// 		for (i = 0; i < sections.length; i++) {
// 			const isv4 = this.isV4Format(sections[i]);
// 			let v4Buffer;

// 			if (isv4) {
// 				v4Buffer = this.toBuffer(sections[i]);
// 				sections[i] = v4Buffer.slice(0, 2).toString('hex');
// 			}

// 			if (v4Buffer && ++i < 8) {
// 				sections.splice(i, 0, v4Buffer.slice(2, 4).toString('hex'));
// 			}
// 		}

// 		if (sections[0] === '') {
// 			while (sections.length < 8) sections.unshift('0');
// 		} else if (sections[sections.length - 1] === '') {
// 			while (sections.length < 8) sections.push('0');
// 		} else if (sections.length < 8) {
// 			for (i = 0; i < sections.length && sections[i] !== ''; i++);
// 			const argv = [i, 1];
// 			for (i = 9 - sections.length; i > 0; i--) {
// 				argv.push('0');
// 			}
// 			sections.splice(...argv);
// 		}

// 		result = buff || Buffer.alloc(offset + 16);
// 		for (i = 0; i < sections.length; i++) {
// 			const word = parseInt(sections[i], 16);
// 			result[offset++] = (word >> 8) & 0xff;
// 			result[offset++] = word & 0xff;
// 		}
// 	}

// 	if (!result) {
// 		throw Error(`Invalid ip address: ${ip}`);
// 	}

// 	return result;
// };

// ip.toString = function (buff, offset, length) {
// 	offset = ~~offset;
// 	length = length || buff.length - offset;

// 	let result = [];
// 	if (length === 4) {
// 		// IPv4
// 		for (let i = 0; i < length; i++) {
// 			result.push(buff[offset + i]);
// 		}
// 		result = result.join('.');
// 	} else if (length === 16) {
// 		// IPv6
// 		for (let i = 0; i < length; i += 2) {
// 			result.push(buff.readUInt16BE(offset + i).toString(16));
// 		}
// 		result = result.join(':');
// 		result = result.replace(/(^|:)0(:0)*:0(:|$)/, '$1::$3');
// 		result = result.replace(/:{3,4}/, '::');
// 	}

// 	return result;
// };

// const ipv4Regex = /^(\d{1,3}\.){3,3}\d{1,3}$/;
// const ipv6Regex =
// 	/^(::)?(((\d{1,3}\.){3}(\d{1,3}){1})?([0-9a-f]){0,4}:{0,2}){1,8}(::)?$/i;

// ip.isV4Format = function (ip) {
// 	return ipv4Regex.test(ip);
// };

// ip.isV6Format = function (ip) {
// 	return ipv6Regex.test(ip);
// };

// function _normalizeFamily(family) {
// 	if (family === 4) {
// 		return 'ipv4';
// 	}
// 	if (family === 6) {
// 		return 'ipv6';
// 	}
// 	return family ? family.toLowerCase() : 'ipv4';
// }

// ip.fromPrefixLen = function (prefixlen, family) {
// 	if (prefixlen > 32) {
// 		family = 'ipv6';
// 	} else {
// 		family = _normalizeFamily(family);
// 	}

// 	let len = 4;
// 	if (family === 'ipv6') {
// 		len = 16;
// 	}
// 	const buff = Buffer.alloc(len);

// 	for (let i = 0, n = buff.length; i < n; ++i) {
// 		let bits = 8;
// 		if (prefixlen < 8) {
// 			bits = prefixlen;
// 		}
// 		prefixlen -= bits;

// 		buff[i] = ~(0xff >> bits) & 0xff;
// 	}

// 	return ip.toString(buff);
// };

// ip.mask = function (addr, mask) {
// 	addr = ip.toBuffer(addr);
// 	mask = ip.toBuffer(mask);

// 	const result = Buffer.alloc(Math.max(addr.length, mask.length));

// 	// Same protocol - do bitwise and
// 	let i;
// 	if (addr.length === mask.length) {
// 		for (i = 0; i < addr.length; i++) {
// 			result[i] = addr[i] & mask[i];
// 		}
// 	} else if (mask.length === 4) {
// 		// IPv6 address and IPv4 mask
// 		// (Mask low bits)
// 		for (i = 0; i < mask.length; i++) {
// 			result[i] = addr[addr.length - 4 + i] & mask[i];
// 		}
// 	} else {
// 		// IPv6 mask and IPv4 addr
// 		for (i = 0; i < result.length - 6; i++) {
// 			result[i] = 0;
// 		}

// 		// ::ffff:ipv4
// 		result[10] = 0xff;
// 		result[11] = 0xff;
// 		for (i = 0; i < addr.length; i++) {
// 			result[i + 12] = addr[i] & mask[i + 12];
// 		}
// 		i += 12;
// 	}
// 	for (; i < result.length; i++) {
// 		result[i] = 0;
// 	}

// 	return ip.toString(result);
// };

// ip.cidr = function (cidrString) {
// 	const cidrParts = cidrString.split('/');

// 	const addr = cidrParts[0];
// 	if (cidrParts.length !== 2) {
// 		throw new Error(`invalid CIDR subnet: ${addr}`);
// 	}

// 	const mask = ip.fromPrefixLen(parseInt(cidrParts[1], 10));

// 	return ip.mask(addr, mask);
// };

// ip.subnet = function (addr, mask) {
// 	const networkAddress = ip.toLong(ip.mask(addr, mask));

// 	// Calculate the mask's length.
// 	const maskBuffer = ip.toBuffer(mask);
// 	let maskLength = 0;

// 	for (let i = 0; i < maskBuffer.length; i++) {
// 		if (maskBuffer[i] === 0xff) {
// 			maskLength += 8;
// 		} else {
// 			let octet = maskBuffer[i] & 0xff;
// 			while (octet) {
// 				octet = (octet << 1) & 0xff;
// 				maskLength++;
// 			}
// 		}
// 	}

// 	const numberOfAddresses = 2 ** (32 - maskLength);

// 	return {
// 		networkAddress: ip.fromLong(networkAddress),
// 		firstAddress:
// 			numberOfAddresses <= 2
// 				? ip.fromLong(networkAddress)
// 				: ip.fromLong(networkAddress + 1),
// 		lastAddress:
// 			numberOfAddresses <= 2
// 				? ip.fromLong(networkAddress + numberOfAddresses - 1)
// 				: ip.fromLong(networkAddress + numberOfAddresses - 2),
// 		broadcastAddress: ip.fromLong(networkAddress + numberOfAddresses - 1),
// 		subnetMask: mask,
// 		subnetMaskLength: maskLength,
// 		numHosts: numberOfAddresses <= 2 ? numberOfAddresses : numberOfAddresses - 2,
// 		length: numberOfAddresses,
// 		contains(other) {
// 			return networkAddress === ip.toLong(ip.mask(other, mask));
// 		},
// 	};
// };

// ip.cidrSubnet = function (cidrString) {
// 	const cidrParts = cidrString.split('/');

// 	const addr = cidrParts[0];
// 	if (cidrParts.length !== 2) {
// 		throw new Error(`invalid CIDR subnet: ${addr}`);
// 	}

// 	const mask = ip.fromPrefixLen(parseInt(cidrParts[1], 10));

// 	return ip.subnet(addr, mask);
// };

// ip.not = function (addr) {
// 	const buff = ip.toBuffer(addr);
// 	for (let i = 0; i < buff.length; i++) {
// 		buff[i] = 0xff ^ buff[i];
// 	}
// 	return ip.toString(buff);
// };

// ip.or = function (a, b) {
// 	a = ip.toBuffer(a);
// 	b = ip.toBuffer(b);

// 	// same protocol
// 	if (a.length === b.length) {
// 		for (let i = 0; i < a.length; ++i) {
// 			a[i] |= b[i];
// 		}
// 		return ip.toString(a);

// 		// mixed protocols
// 	}
// 	let buff = a;
// 	let other = b;
// 	if (b.length > a.length) {
// 		buff = b;
// 		other = a;
// 	}

// 	const offset = buff.length - other.length;
// 	for (let i = offset; i < buff.length; ++i) {
// 		buff[i] |= other[i - offset];
// 	}

// 	return ip.toString(buff);
// };

// ip.isEqual = function (a, b) {
// 	a = ip.toBuffer(a);
// 	b = ip.toBuffer(b);

// 	// Same protocol
// 	if (a.length === b.length) {
// 		for (let i = 0; i < a.length; i++) {
// 			if (a[i] !== b[i]) return false;
// 		}
// 		return true;
// 	}

// 	// Swap
// 	if (b.length === 4) {
// 		const t = b;
// 		b = a;
// 		a = t;
// 	}

// 	// a - IPv4, b - IPv6
// 	for (let i = 0; i < 10; i++) {
// 		if (b[i] !== 0) return false;
// 	}

// 	const word = b.readUInt16BE(10);
// 	if (word !== 0 && word !== 0xffff) return false;

// 	for (let i = 0; i < 4; i++) {
// 		if (a[i] !== b[i + 12]) return false;
// 	}

// 	return true;
// };

// ip.isPrivate = function (addr) {
// 	return (
// 		/^(::f{4}:)?10\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(addr) ||
// 		/^(::f{4}:)?192\.168\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(addr) ||
// 		/^(::f{4}:)?172\.(1[6-9]|2\d|30|31)\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(addr) ||
// 		/^(::f{4}:)?127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(addr) ||
// 		/^(::f{4}:)?169\.254\.([0-9]{1,3})\.([0-9]{1,3})$/i.test(addr) ||
// 		/^f[cd][0-9a-f]{2}:/i.test(addr) ||
// 		/^fe80:/i.test(addr) ||
// 		/^::1$/.test(addr) ||
// 		/^::$/.test(addr)
// 	);
// };

// ip.isPublic = function (addr) {
// 	return !ip.isPrivate(addr);
// };

// ip.isLoopback = function (addr) {
// 	return (
// 		/^(::f{4}:)?127\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/.test(addr) ||
// 		/^fe80::1$/.test(addr) ||
// 		/^::1$/.test(addr) ||
// 		/^::$/.test(addr)
// 	);
// };

// ip.loopback = function (family) {
// 	//
// 	// Default to `ipv4`
// 	//
// 	family = _normalizeFamily(family);

// 	if (family !== 'ipv4' && family !== 'ipv6') {
// 		throw new Error('family must be ipv4 or ipv6');
// 	}

// 	return family === 'ipv4' ? '127.0.0.1' : 'fe80::1';
// };

// //
// // ### function address (name, family)
// // #### @name {string|'public'|'private'} **Optional** Name or security
// //      of the network interface.
// // #### @family {ipv4|ipv6} **Optional** IP family of the address (defaults
// //      to ipv4).
// //
// // Returns the address for the network interface on the current system with
// // the specified `name`:
// //   * String: First `family` address of the interface.
// //             If not found see `undefined`.
// //   * 'public': the first public ip address of family.
// //   * 'private': the first private ip address of family.
// //   * undefined: First address with `ipv4` or loopback address `127.0.0.1`.
// //
// ip.address = function (name, family) {
// 	const interfaces = os.networkInterfaces();

// 	//
// 	// Default to `ipv4`
// 	//
// 	family = _normalizeFamily(family);

// 	//
// 	// If a specific network interface has been named,
// 	// return the address.
// 	//
// 	if (name && name !== 'private' && name !== 'public') {
// 		const res = interfaces[name].filter((details) => {
// 			const itemFamily = _normalizeFamily(details.family);
// 			return itemFamily === family;
// 		});
// 		if (res.length === 0) {
// 			return undefined;
// 		}
// 		return res[0].address;
// 	}

// 	const all = Object.keys(interfaces)
// 		.map((nic) => {
// 			//
// 			// Note: name will only be `public` or `private`
// 			// when this is called.
// 			//
// 			const addresses = interfaces[nic].filter((details) => {
// 				details.family = _normalizeFamily(details.family);
// 				if (details.family !== family || ip.isLoopback(details.address)) {
// 					return false;
// 				}
// 				if (!name) {
// 					return true;
// 				}

// 				return name === 'public'
// 					? ip.isPrivate(details.address)
// 					: ip.isPublic(details.address);
// 			});

// 			return addresses.length ? addresses[0].address : undefined;
// 		})
// 		.filter(Boolean);

// 	return !all.length ? ip.loopback(family) : all[0];
// };

// ip.toLong = function (ip) {
// 	let ipl = 0;
// 	ip.split('.').forEach((octet) => {
// 		ipl <<= 8;
// 		ipl += parseInt(octet);
// 	});
// 	return ipl >>> 0;
// };

// ip.fromLong = function (ipl) {
// 	return `${ipl >>> 24}.${(ipl >> 16) & 255}.${(ipl >> 8) & 255}.${ipl & 255}`;
// };

// /* global describe, it */
// const assert = require('assert');
// const {Buffer} = require('buffer');
// const net = require('net');
// const os = require('os');
// const ip = require('..');

// describe('IP library for node.js', () => {
// 	describe('toBuffer()/toString() methods', () => {
// 		it('should convert to buffer IPv4 address', () => {
// 			const buf = ip.toBuffer('127.0.0.1');
// 			assert.equal(buf.toString('hex'), '7f000001');
// 			assert.equal(ip.toString(buf), '127.0.0.1');
// 		});

// 		it('should convert to buffer IPv4 address in-place', () => {
// 			const buf = new Buffer(128);
// 			const offset = 64;
// 			ip.toBuffer('127.0.0.1', buf, offset);
// 			assert.equal(buf.toString('hex', offset, offset + 4), '7f000001');
// 			assert.equal(ip.toString(buf, offset, 4), '127.0.0.1');
// 		});

// 		it('should convert to buffer IPv6 address', () => {
// 			const buf = ip.toBuffer('::1');
// 			assert(/(00){15,15}01/.test(buf.toString('hex')));
// 			assert.equal(ip.toString(buf), '::1');
// 			assert.equal(ip.toString(ip.toBuffer('1::')), '1::');
// 			assert.equal(ip.toString(ip.toBuffer('abcd::dcba')), 'abcd::dcba');
// 		});

// 		it('should convert to buffer IPv6 address in-place', () => {
// 			const buf = new Buffer(128);
// 			const offset = 64;
// 			ip.toBuffer('::1', buf, offset);
// 			assert(/(00){15,15}01/.test(buf.toString('hex', offset, offset + 16)));
// 			assert.equal(ip.toString(buf, offset, 16), '::1');
// 			assert.equal(ip.toString(ip.toBuffer('1::', buf, offset), offset, 16), '1::');
// 			assert.equal(
// 				ip.toString(ip.toBuffer('abcd::dcba', buf, offset), offset, 16),
// 				'abcd::dcba',
// 			);
// 		});

// 		it('should convert to buffer IPv6 mapped IPv4 address', () => {
// 			let buf = ip.toBuffer('::ffff:127.0.0.1');
// 			assert.equal(buf.toString('hex'), '00000000000000000000ffff7f000001');
// 			assert.equal(ip.toString(buf), '::ffff:7f00:1');

// 			buf = ip.toBuffer('ffff::127.0.0.1');
// 			assert.equal(buf.toString('hex'), 'ffff000000000000000000007f000001');
// 			assert.equal(ip.toString(buf), 'ffff::7f00:1');

// 			buf = ip.toBuffer('0:0:0:0:0:ffff:127.0.0.1');
// 			assert.equal(buf.toString('hex'), '00000000000000000000ffff7f000001');
// 			assert.equal(ip.toString(buf), '::ffff:7f00:1');
// 		});
// 	});

// 	describe('fromPrefixLen() method', () => {
// 		it('should create IPv4 mask', () => {
// 			assert.equal(ip.fromPrefixLen(24), '255.255.255.0');
// 		});
// 		it('should create IPv6 mask', () => {
// 			assert.equal(ip.fromPrefixLen(64), 'ffff:ffff:ffff:ffff::');
// 		});
// 		it('should create IPv6 mask explicitly', () => {
// 			assert.equal(ip.fromPrefixLen(24, 'IPV6'), 'ffff:ff00::');
// 		});
// 	});

// 	describe('not() method', () => {
// 		it('should reverse bits in address', () => {
// 			assert.equal(ip.not('255.255.255.0'), '0.0.0.255');
// 		});
// 	});

// 	describe('or() method', () => {
// 		it('should or bits in ipv4 addresses', () => {
// 			assert.equal(ip.or('0.0.0.255', '192.168.1.10'), '192.168.1.255');
// 		});
// 		it('should or bits in ipv6 addresses', () => {
// 			assert.equal(ip.or('::ff', '::abcd:dcba:abcd:dcba'), '::abcd:dcba:abcd:dcff');
// 		});
// 		it('should or bits in mixed addresses', () => {
// 			assert.equal(ip.or('0.0.0.255', '::abcd:dcba:abcd:dcba'), '::abcd:dcba:abcd:dcff');
// 		});
// 	});

// 	describe('mask() method', () => {
// 		it('should mask bits in address', () => {
// 			assert.equal(ip.mask('192.168.1.134', '255.255.255.0'), '192.168.1.0');
// 			assert.equal(ip.mask('192.168.1.134', '::ffff:ff00'), '::ffff:c0a8:100');
// 		});

// 		it('should not leak data', () => {
// 			for (let i = 0; i < 10; i++) {
// 				assert.equal(ip.mask('::1', '0.0.0.0'), '::');
// 			}
// 		});
// 	});

// 	describe('subnet() method', () => {
// 		// Test cases calculated with http://www.subnet-calculator.com/
// 		const ipv4Subnet = ip.subnet('192.168.1.134', '255.255.255.192');

// 		it('should compute ipv4 network address', () => {
// 			assert.equal(ipv4Subnet.networkAddress, '192.168.1.128');
// 		});

// 		it("should compute ipv4 network's first address", () => {
// 			assert.equal(ipv4Subnet.firstAddress, '192.168.1.129');
// 		});

// 		it("should compute ipv4 network's last address", () => {
// 			assert.equal(ipv4Subnet.lastAddress, '192.168.1.190');
// 		});

// 		it('should compute ipv4 broadcast address', () => {
// 			assert.equal(ipv4Subnet.broadcastAddress, '192.168.1.191');
// 		});

// 		it('should compute ipv4 subnet number of addresses', () => {
// 			assert.equal(ipv4Subnet.length, 64);
// 		});

// 		it('should compute ipv4 subnet number of addressable hosts', () => {
// 			assert.equal(ipv4Subnet.numHosts, 62);
// 		});

// 		it('should compute ipv4 subnet mask', () => {
// 			assert.equal(ipv4Subnet.subnetMask, '255.255.255.192');
// 		});

// 		it("should compute ipv4 subnet mask's length", () => {
// 			assert.equal(ipv4Subnet.subnetMaskLength, 26);
// 		});

// 		it('should know whether a subnet contains an address', () => {
// 			assert.equal(ipv4Subnet.contains('192.168.1.180'), true);
// 		});

// 		it('should know whether a subnet does not contain an address', () => {
// 			assert.equal(ipv4Subnet.contains('192.168.1.195'), false);
// 		});
// 	});

// 	describe('subnet() method with mask length 32', () => {
// 		// Test cases calculated with http://www.subnet-calculator.com/
// 		const ipv4Subnet = ip.subnet('192.168.1.134', '255.255.255.255');
// 		it("should compute ipv4 network's first address", () => {
// 			assert.equal(ipv4Subnet.firstAddress, '192.168.1.134');
// 		});

// 		it("should compute ipv4 network's last address", () => {
// 			assert.equal(ipv4Subnet.lastAddress, '192.168.1.134');
// 		});

// 		it('should compute ipv4 subnet number of addressable hosts', () => {
// 			assert.equal(ipv4Subnet.numHosts, 1);
// 		});
// 	});

// 	describe('subnet() method with mask length 31', () => {
// 		// Test cases calculated with http://www.subnet-calculator.com/
// 		const ipv4Subnet = ip.subnet('192.168.1.134', '255.255.255.254');
// 		it("should compute ipv4 network's first address", () => {
// 			assert.equal(ipv4Subnet.firstAddress, '192.168.1.134');
// 		});

// 		it("should compute ipv4 network's last address", () => {
// 			assert.equal(ipv4Subnet.lastAddress, '192.168.1.135');
// 		});

// 		it('should compute ipv4 subnet number of addressable hosts', () => {
// 			assert.equal(ipv4Subnet.numHosts, 2);
// 		});
// 	});

// 	describe('cidrSubnet() method', () => {
// 		// Test cases calculated with http://www.subnet-calculator.com/
// 		const ipv4Subnet = ip.cidrSubnet('192.168.1.134/26');

// 		it('should compute an ipv4 network address', () => {
// 			assert.equal(ipv4Subnet.networkAddress, '192.168.1.128');
// 		});

// 		it("should compute an ipv4 network's first address", () => {
// 			assert.equal(ipv4Subnet.firstAddress, '192.168.1.129');
// 		});

// 		it("should compute an ipv4 network's last address", () => {
// 			assert.equal(ipv4Subnet.lastAddress, '192.168.1.190');
// 		});

// 		it('should compute an ipv4 broadcast address', () => {
// 			assert.equal(ipv4Subnet.broadcastAddress, '192.168.1.191');
// 		});

// 		it('should compute an ipv4 subnet number of addresses', () => {
// 			assert.equal(ipv4Subnet.length, 64);
// 		});

// 		it('should compute an ipv4 subnet number of addressable hosts', () => {
// 			assert.equal(ipv4Subnet.numHosts, 62);
// 		});

// 		it('should compute an ipv4 subnet mask', () => {
// 			assert.equal(ipv4Subnet.subnetMask, '255.255.255.192');
// 		});

// 		it("should compute an ipv4 subnet mask's length", () => {
// 			assert.equal(ipv4Subnet.subnetMaskLength, 26);
// 		});

// 		it('should know whether a subnet contains an address', () => {
// 			assert.equal(ipv4Subnet.contains('192.168.1.180'), true);
// 		});

// 		it('should know whether a subnet contains an address', () => {
// 			assert.equal(ipv4Subnet.contains('192.168.1.195'), false);
// 		});
// 	});

// 	describe('cidr() method', () => {
// 		it('should mask address in CIDR notation', () => {
// 			assert.equal(ip.cidr('192.168.1.134/26'), '192.168.1.128');
// 			assert.equal(ip.cidr('2607:f0d0:1002:51::4/56'), '2607:f0d0:1002::');
// 		});
// 	});

// 	describe('isEqual() method', () => {
// 		it('should check if addresses are equal', () => {
// 			assert(ip.isEqual('127.0.0.1', '::7f00:1'));
// 			assert(!ip.isEqual('127.0.0.1', '::7f00:2'));
// 			assert(ip.isEqual('127.0.0.1', '::ffff:7f00:1'));
// 			assert(!ip.isEqual('127.0.0.1', '::ffaf:7f00:1'));
// 			assert(ip.isEqual('::ffff:127.0.0.1', '::ffff:127.0.0.1'));
// 			assert(ip.isEqual('::ffff:127.0.0.1', '127.0.0.1'));
// 		});
// 	});

// 	describe('isPrivate() method', () => {
// 		it('should check if an address is localhost', () => {
// 			assert.equal(ip.isPrivate('127.0.0.1'), true);
// 		});

// 		it('should check if an address is from a 192.168.x.x network', () => {
// 			assert.equal(ip.isPrivate('192.168.0.123'), true);
// 			assert.equal(ip.isPrivate('192.168.122.123'), true);
// 			assert.equal(ip.isPrivate('192.162.1.2'), false);
// 		});

// 		it('should check if an address is from a 172.16.x.x network', () => {
// 			assert.equal(ip.isPrivate('172.16.0.5'), true);
// 			assert.equal(ip.isPrivate('172.16.123.254'), true);
// 			assert.equal(ip.isPrivate('171.16.0.5'), false);
// 			assert.equal(ip.isPrivate('172.25.232.15'), true);
// 			assert.equal(ip.isPrivate('172.15.0.5'), false);
// 			assert.equal(ip.isPrivate('172.32.0.5'), false);
// 		});

// 		it('should check if an address is from a 169.254.x.x network', () => {
// 			assert.equal(ip.isPrivate('169.254.2.3'), true);
// 			assert.equal(ip.isPrivate('169.254.221.9'), true);
// 			assert.equal(ip.isPrivate('168.254.2.3'), false);
// 		});

// 		it('should check if an address is from a 10.x.x.x network', () => {
// 			assert.equal(ip.isPrivate('10.0.2.3'), true);
// 			assert.equal(ip.isPrivate('10.1.23.45'), true);
// 			assert.equal(ip.isPrivate('12.1.2.3'), false);
// 		});

// 		it('should check if an address is from a private IPv6 network', () => {
// 			assert.equal(ip.isPrivate('fd12:3456:789a:1::1'), true);
// 			assert.equal(ip.isPrivate('fe80::f2de:f1ff:fe3f:307e'), true);
// 			assert.equal(ip.isPrivate('::ffff:10.100.1.42'), true);
// 			assert.equal(ip.isPrivate('::FFFF:172.16.200.1'), true);
// 			assert.equal(ip.isPrivate('::ffff:192.168.0.1'), true);
// 		});

// 		it('should check if an address is from the internet', () => {
// 			assert.equal(ip.isPrivate('165.225.132.33'), false); // joyent.com
// 		});

// 		it('should check if an address is a loopback IPv6 address', () => {
// 			assert.equal(ip.isPrivate('::'), true);
// 			assert.equal(ip.isPrivate('::1'), true);
// 			assert.equal(ip.isPrivate('fe80::1'), true);
// 		});
// 	});

// 	describe('loopback() method', () => {
// 		describe('undefined', () => {
// 			it('should respond with 127.0.0.1', () => {
// 				assert.equal(ip.loopback(), '127.0.0.1');
// 			});
// 		});

// 		describe('ipv4', () => {
// 			it('should respond with 127.0.0.1', () => {
// 				assert.equal(ip.loopback('ipv4'), '127.0.0.1');
// 			});
// 		});

// 		describe('ipv6', () => {
// 			it('should respond with fe80::1', () => {
// 				assert.equal(ip.loopback('ipv6'), 'fe80::1');
// 			});
// 		});
// 	});

// 	describe('isLoopback() method', () => {
// 		describe('127.0.0.1', () => {
// 			it('should respond with true', () => {
// 				assert.ok(ip.isLoopback('127.0.0.1'));
// 			});
// 		});

// 		describe('127.8.8.8', () => {
// 			it('should respond with true', () => {
// 				assert.ok(ip.isLoopback('127.8.8.8'));
// 			});
// 		});

// 		describe('8.8.8.8', () => {
// 			it('should respond with false', () => {
// 				assert.equal(ip.isLoopback('8.8.8.8'), false);
// 			});
// 		});

// 		describe('fe80::1', () => {
// 			it('should respond with true', () => {
// 				assert.ok(ip.isLoopback('fe80::1'));
// 			});
// 		});

// 		describe('::1', () => {
// 			it('should respond with true', () => {
// 				assert.ok(ip.isLoopback('::1'));
// 			});
// 		});

// 		describe('::', () => {
// 			it('should respond with true', () => {
// 				assert.ok(ip.isLoopback('::'));
// 			});
// 		});
// 	});

// 	describe('address() method', () => {
// 		describe('undefined', () => {
// 			it('should respond with a private ip', () => {
// 				assert.ok(ip.isPrivate(ip.address()));
// 			});
// 		});

// 		describe('private', () => {
// 			[undefined, 'ipv4', 'ipv6'].forEach((family) => {
// 				describe(family || 'undefined', () => {
// 					it('should respond with a private ip', () => {
// 						assert.ok(ip.isPrivate(ip.address('private', family)));
// 					});
// 				});
// 			});
// 		});

// 		const interfaces = os.networkInterfaces();

// 		Object.keys(interfaces).forEach((nic) => {
// 			describe(nic, () => {
// 				[undefined, 'ipv4'].forEach((family) => {
// 					describe(family || 'undefined', () => {
// 						it('should respond with an ipv4 address', () => {
// 							const addr = ip.address(nic, family);
// 							assert.ok(!addr || net.isIPv4(addr));
// 						});
// 					});
// 				});

// 				describe('ipv6', () => {
// 					it('should respond with an ipv6 address', () => {
// 						const addr = ip.address(nic, 'ipv6');
// 						assert.ok(!addr || net.isIPv6(addr));
// 					});
// 				});
// 			});
// 		});
// 	});

// 	describe('toLong() method', () => {
// 		it('should respond with a int', () => {
// 			assert.equal(ip.toLong('127.0.0.1'), 2130706433);
// 			assert.equal(ip.toLong('255.255.255.255'), 4294967295);
// 		});
// 	});

// 	describe('fromLong() method', () => {
// 		it('should repond with ipv4 address', () => {
// 			assert.equal(ip.fromLong(2130706433), '127.0.0.1');
// 			assert.equal(ip.fromLong(4294967295), '255.255.255.255');
// 		});
// 	});
// });
