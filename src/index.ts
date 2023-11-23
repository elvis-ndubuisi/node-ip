import {isIPv4, isIPv6} from 'net';

export type IPFamily = 'ipv4' | 'ipv6';
export type IPBuffer = Buffer;

const ipv4Regex =
	/^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])){3}$/;
const ipv6Regex =
	/^([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:$|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$|^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$|^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$|^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$|^([0-9a-fA-F]{1,4}:){1,6}(:[0-9a-fA-F]{1,4}){1,2}$|^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,3}$|^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,4}$|^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,5}$|^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,6}$|^([0-9a-fA-F]{1,4}:){1,7}(:[0-9a-fA-F]{1,4})$|^::(?:ffff:)?(?:\d{1,3}\.){3}\d{1,3}$|^::1$/;

/**
 * Checks if the provided string is in IPv4 format.
 *
 * @param ip The string to check.
 * @returns True if the string is in IPv4 format, false otherwise.
 */
export const isV4Format = (ip: string): boolean => ipv4Regex.test(ip);

/**
 * Checks if the provided string is in IPv6 format.
 *
 * @param ip The string to check.
 * @returns True if the string is in IPv6 format, false otherwise.
 */
export const isV6Format = (ip: string): boolean => ipv6Regex.test(ip);

/**
 * Converts an IP address to a Buffer.
 *
 * @param ip {string} - The IP address to convert
 * @param buffer {Buffer} - The Buffer to store the result (optional)
 * @param offset {number} - The offset in the Buffer to start writing.
 * @returns The Buffer representation of the IP address.
 * @throws {Error} If the provided IP address is invalid.
 *
 * @example
 * toBuffer('192.168.1.1', buffer, 0);
 * console.log(buffer); // Output: <Buffer c0 a8 01 01>
 */
export const toBuffer = (ip: string, buffer?: Buffer, offset: number = 0): Buffer => {
	offset = Math.floor(offset);

	ip = ip.trim();
	let result: Buffer | undefined;

	if (isIPv4(ip)) {
		result = buffer || Buffer.alloc(offset + 4);
		const bytes = ip.split('.').map((byte) => parseInt(byte, 10) & 0xff);
		result.set(bytes, offset);
	} else if (isIPv6(ip)) {
		result = buffer || Buffer.alloc(offset + 16);

		// Handle IPv6 loopback address
		if (ip === '::1') {
			result.fill(0, offset, offset + 16);
			result.writeUInt16BE(1, offset + 14); // Set the last 16 bits to 1
		} else {
			const parsedIPv6 = ip.split(':').map((section) => parseInt(section, 16));

			// Handle :: in IPv6 address
			const expandIdx = parsedIPv6.indexOf(0);
			if (expandIdx !== -1) {
				parsedIPv6.splice(expandIdx, 1, ...new Array(9 - parsedIPv6.length).fill(0));
			}
			for (let i = 0; i < 8; i++) {
				result.writeUInt16BE(parsedIPv6[i] || 0, offset);
				offset += 2;
			}
		}
	}

	if (!result) throw new Error(`Invalid IP address: ${ip}`);

	return result;
};

/**
 * Converts a portion of a Buffer to a string representation based on the specified length.
 *
 * @param buffer {Buffer} - The Buffer to extract data from.
 * @param offset {number} - The starting offset in the Buffer.
 * @param length {number} - The number of bytes to consider from the Buffer (default is the remaining length from offset).
 * @returns {string} - The string representation of the Buffer data.
 *
 * @example
 * const buffer = Buffer.from('00000000000000000000000000000001', 'hex');
 * const ipv6String = toString(buffer, 0, 16);
 * console.log(ipv6String); // Output: '0000:0000:0000:0000:0000:0000:0000:0001'
 */
const toString = (buffer: Buffer, offset: number, length?: number): string => {
	offset = Math.floor(offset);
	length = length || buffer.length - offset;

	if (buffer.length < offset + length) {
		throw new Error('Invalid offset and length combination, exceeds buffer size.');
	}

	const portion = buffer.subarray(offset, offset + length); // Extract portion of the buffer

	if(portion.length === 4){}else if(portion.length === 16){}else {

	}

	// let result: string | string[] = [];

	// if (length === 4) {
	// 	// IPv4
	// 	// for (let i = 0; i < length; i++) {
	// 	// result.push(buffer[offset + i].toString());
	// 	// }
	// 	// result = result.join('.');
	// 	result = Array.from(slice).join('.');
	// } else if (length === 16) {
	// 	// IPv6
	// 	for (let i = 0; i < length; i += 2) {
	// 		result.push(buffer.readUInt16BE(offset + i).toString(16));
	// 		// if (offset + i + 1 < buffer.length) {
	// 		// result.push(buffer.readUInt16BE(offset + i).toString(16));
	// 		// }
	// 	}
	// 	result = result.join(':');

	// 	// IPv6 Compression Handling
	// 	result = result.replace(/(^|(?<=:))0(?=:|$)/g, ''); // Remove leading zeros
	// 	result = result.replace(/:{2,}/g, '::'); // Replace multiple colons with '::'
	// } else {
	// 	throw new Error('Unsupported length for string conversion');
	// }

	// return result as string;
};

/**
 * Generate an IP address from a given prefix length and address family.
 *
 * @param prefixlen - Non-negative integer representing the prefix length for the IP address.
 * @param family - Address family for the IP address. Can be a number (4 or 6) or a string ('ipv4', 'ipv6').
 * Defaults to 'ipv4' if not provided.
 *
 * @returns Generated IP address as a string based on the specified prefix length and address family.
 *
 * @remarks
 * If the prefix length is greater than 32 and family is not explicitly specified as IPv6, it defaults to IPv6.
 *
 * @example
 * // Generate IPv4 address with prefix length 24
 * fromPrefixLen(24, 'ipv4'); // Returns IPv4 address
 *
 * // Generate IPv6 address with prefix length 128
 * fromPrefixLen(128, 'ipv6'); // Returns IPv6 address
 *
 * // Generate IPv6 address with prefix length 128 (auto-detected family)
 * fromPrefixLen(128, 6); // Returns IPv6 address
 */
export const fromPrefixLen = (
	prefixlen: number,
	family: 'ipv4' | 'ipv6' | 4 | 6 = 'ipv4',
): string => {
	// Handle error for non-negative length
	if (prefixlen < 0) {
		throw new Error('Prefix length must be a non-negative integer.');
	}

	// Handle error for ipv6 length > 128
	if ((family === 'ipv6' || family === 6) && prefixlen > 128) {
		throw new Error('Invalid prefix length for IPv6 address.');
	}

	if (prefixlen > 32) {
		family = 'ipv6';
	} else {
		family = normalizeFamily(family);
	}

	let len = 4;
	if (family === 'ipv6') len = 16;

	const buffer = Buffer.alloc(len);

	for (let i = 0, n = buffer.length; i < n; ++i) {
		let bits = 8;
		if (prefixlen < 8) {
			bits = prefixlen;
		}
		prefixlen -= bits;

		buffer[i] = ~(0xff >> bits) & 0xff;
	}

	return toString(buffer, 0);
};

/**
 * Apply a network mask to an IP address, performing a bitwise AND operation.
 *
 * @param addr - The IP address to be masked.
 * @param mask - The network mask to apply to the IP address.
 *
 * @returns The resulting IP address after applying the network mask.
 *
 * @remarks
 * If the mask is an IPv4 address, only the corresponding low bits are used.
 * If the mask is an IPv6 address, it is applied to the IPv4-mapped part of the address (::ffff:ipv4).
 *
 * @example
 * // Apply an IPv4 mask to an IPv4 address
 * mask('192.168.1.10', '255.255.255.0'); // Returns '192.168.1.0'
 *
 * // Apply an IPv6 mask to an IPv6 address
 * mask('2001:db8::1', 'ffff:ffff:ffff:ffff::'); // Returns '2001:db8::'
 *
 * // Apply an IPv6 mask to an IPv4-mapped IPv6 address
 * mask('::ffff:192.168.1.10', 'ffff:ffff:ffff:ffff::'); // Returns '::ffff:192.168.1.0'
 */
export const mask = (addr: string, mask: string): string => {
	const addrBuffer = toBuffer(addr) as IPBuffer;
	const maskBuffer = toBuffer(mask) as IPBuffer;

	const resultLength = Math.max(addrBuffer.length, maskBuffer.length);
	const result = Buffer.alloc(resultLength);

	// Same protocol - do bitwise AND
	for (let i = 0; i < Math.min(addrBuffer.length, maskBuffer.length); i++) {
		result[i] = addrBuffer[i] & maskBuffer[i];
	}

	if (maskBuffer.length === 16) {
		// IPv6 mask
		for (let i = 0; i < result.length; i++) {
			result[i] = addrBuffer[i] & maskBuffer[i];
		}
	} else if (maskBuffer.length === 4) {
		// IPv4 mask
		// (Mask low bits)
		for (let i = 0; i < maskBuffer.length; i++) {
			result[i] = addrBuffer[addrBuffer.length - 4 + i] & maskBuffer[i];
		}
	}

	return toString(result, 0);
};

/**
 * Applies CIDR subnet masking to the given IP address.
 *
 * @param cidrStr - The CIDR-formatted subnet, e.g., '192.168.1.0/24'.
 * @returns The masked IP address.
 * @throws {Error} If the CIDR subnet is invalid.
 */
export const cidr = (cidrStr: string): string => {
	const cidrParts = cidrStr.split('/');

	if (cidrParts.length !== 2) {
		throw new Error(`Invalid CIDR subnet: ${cidrStr}`);
	}

	const address = cidrParts[0];
	const prefixLen = parseInt(cidrParts[1], 10);

	if (isNaN(prefixLen) || prefixLen < 0) {
		throw new Error(`Invalid prefix length: ${cidrParts[1]}`);
	}

	const family = address.includes(':') ? 'ipv6' : 'ipv4';
	const msk = fromPrefixLen(prefixLen, family);

	return mask(address, msk);
};

/**
 * Converts an IPv4 address string to its corresponding 32-bit unsigned integer representation.
 * @param ip - The IPv4 address string to convert.
 * @returns The 32-bit unsigned integer representation of the IPv4 address.
 * @throws {Error} If the input is not a valid IPv4 address.
 */
export const toLong = (ip: string): number => {
	const ipv4Regex =
		/^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})){3}$/;

	if (!ipv4Regex.test(ip)) {
		throw new Error('Invalid IPv4 address format');
	}

	let ipl = 0;
	ip.split('.').forEach((octet) => {
		ipl <<= 8;
		ipl += parseInt(octet, 10);
	});

	return ipl >>> 0;
};

interface ISubnet {
	networkAddress: string;
	firstAddress: string;
	lastAddress: string;
	broadcastAddress: string;
	subnetMask: string;
	subnetMaskLength: number;
	numHosts: number;
	length: number;
	contains(other: string): boolean;
}

export const subnet = (addr: string, msk: string): ISubnet => {
	const networkAddress = toLong(mask(addr, msk));

	// Calculate the mask's length.
	const maskBuffer = toBuffer(msk);
	let maskLength = 0;

	for (let i = 0; i < maskBuffer.length; i++) {
		if (maskBuffer[i] === 0xff) {
			maskLength += 8;
		} else {
			let octet = maskBuffer[i] & 0xff;
			while (octet) {
				octet = (octet << 1) & 0xff;
				maskLength++;
			}
		}
	}

	const numberOfAddresses = 2 ** (32 - maskLength);

	const result: ISubnet = {
		networkAddress: fromLong(networkAddress),
		firstAddress:
			numberOfAddresses <= 2 ? fromLong(networkAddress) : fromLong(networkAddress + 1),
		lastAddress:
			numberOfAddresses <= 2
				? fromLong(networkAddress + numberOfAddresses - 1)
				: fromLong(networkAddress + numberOfAddresses - 2),
		broadcastAddress: fromLong(networkAddress + numberOfAddresses - 1),
		subnetMask: msk,
		subnetMaskLength: maskLength,
		numHosts: numberOfAddresses <= 2 ? numberOfAddresses : numberOfAddresses - 2,
		length: numberOfAddresses,
		contains(other: string): boolean {
			return networkAddress === toLong(mask(other, msk));
		},
	};

	return result;
};

export const cidrSubnet = () => {};

export const not = () => {};

export const or = () => {};

export const isEqual = () => {};

export const isPrivate = () => {};

export const isPublic = () => {};

export const isLoopback = () => {};

export const loopback = () => {};

export const address = () => {};

export const fromLong = () => {};

const nodeIP = {
	address,
	cidr,
	cidrSubnet,
	fromLong,
	fromPrefixLen,
	ipv4Regex,
	ipv6Regex,
	isEqual,
	toLong,
	isLoopback,
	isPrivate,
	isPublic,
	isV4Format,
	isV6Format,
	loopback,
	mask,
	not,
	or,
	toBuffer,
	toString,
};

export default nodeIP;

/**
 * Normalize and provide a standardized string representation for Internet Protocol (IP) address families.
 *
 * @param family - The address family to be normalized. It can be either a number (4 or 6) representing IPv4 or IPv6,
 * or a string (case-insensitive) such as 'ipv4', 'ipv6', 'IPv4', 'IPv6', etc.
 *
 * @returns A normalized string representation of the address family:
 * - If family is 4, it returns 'ipv4'.
 * - If family is 6, it returns 'ipv6'.
 * - If family is a truthy string (other than 4 or 6), it returns the lowercase representation of the string.
 * - If family is falsy (undefined or null), it defaults to 'ipv4'.
 *
 * @example
 * // IPv4 Family
 * normalizeFamily(4); // Returns 'ipv4'
 *
 * // IPv6 Family
 * normalizeFamily(6); // Returns 'ipv6'
 *
 * // Case-Insensitive String Representation
 * normalizeFamily('IPv4'); // Returns 'ipv4'
 * normalizeFamily('IPv6'); // Returns 'ipv6'
 *
 * / Default Case
 * normalizeFamily(undefined); // Returns 'ipv4'
 */
export function normalizeFamily(family: string | number | undefined): IPFamily {
	if (family === 4) return 'ipv4';
	if (family === 6) return 'ipv6';

	return family ? ((family as string).toLowerCase() as IPFamily) : 'ipv4';
}
