const ipv4Regex = /^(\d{1,3}\.){3,3}\d{1,3}$/;
const ipv6Regex =
	/^(::)?(((\d{1,3}\.){3}(\d{1,3}){1})?([0-9a-f]){0,4}:{0,2}){1,8}(::)?$/i;

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
 * @param ip string - The IP address to convert
 * @param buff Buffer - The Buffer to store the result
 * @param offset number - The offset in the Buffer to start writing.
 *
 * @example
 * toBuffer('192.168.1.1', buffer, 0);
 * console.log(buffer); // Output: <Buffer c0 a8 01 01>
 */
export const toBuffer = (ip: string, buffer?: Buffer, offset: number = 0): Buffer => {
	offset = Math.floor(offset);
	let result: Buffer | undefined;

	// Check ip formats
	if (isV4Format(ip)) {
		result = buffer || Buffer.alloc(offset + 4);
		ip.split(/\./g).map((byte) => {
			result[offset++] = parseInt(byte, 10) & 0xff;
		});
	} else if (isV6Format(ip)) {
		const sections = ip.split(':', 8);

		let idx: number;

		for (idx = 0; idx < sections.length; idx++) {
			const isv4 = isV4Format(sections[idx]);
			let v4Buffer;

			if (isv4) {
				v4Buffer = toBuffer(sections[idx]);
				sections[idx] = v4Buffer.subarray(0, 2).toString('hex');
			}

			if (v4Buffer && ++idx < 8) {
				sections.splice(idx, 0, v4Buffer.subarray(2, 4).toString('hex'));
			}
		}

		if (sections[0] === '') {
			while (sections.length < 8) sections.unshift('0');
		} else if (sections[sections.length - 1] === '') {
			while (sections.length < 8) sections.push('0');
		} else if (sections.length < 8) {
			for (idx = 0; idx < sections.length && sections[idx] !== ''; idx++) {
				const argv = [idx, 1];
				for (idx = 9 - sections.length; idx > 0; idx--) {
					argv.push(0);
				}
				sections.splice(...argv);
			}

			result = buffer || Buffer.alloc(offset + 16);

			for (idx = 0; idx < sections.length; idx++) {
				const word = parseInt(sections[idx], 16);
				result[offset++] = (word >> 8) & 0xff;
				result[offset++] = word & 0xff;
			}
		}
	}

	if (!result) throw Error(`Invalid IP address :: ${ip}`);

	return result;
};

export const nodeIP = {
	ipv4Regex,
	ipv6Regex,
};
