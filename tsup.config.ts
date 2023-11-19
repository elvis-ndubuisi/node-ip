import {defineConfig} from 'tsup';

export default defineConfig({
	entry: ['src/index.ts'],
	outDir: 'dist',
	format: ['cjs', 'esm'],
	target: 'es2018',
	dts: true,
});
