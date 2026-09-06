import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
	site: 'https://pmdroid.github.io',
	base: '/tesla-vehicle-command',
	integrations: [
		starlight({
			title: 'TeslaBLE',
			description: 'C++ library for Tesla vehicle-command over BLE',
			social: [
				{
					icon: 'github',
					label: 'GitHub',
					href: 'https://github.com/pmdroid/tesla-vehicle-command',
				},
			],
			sidebar: [
				{
					label: 'Use the library',
					items: [
						{ label: 'Install', slug: 'install' },
						{ label: 'Pair a key', slug: 'pair' },
						{ label: 'Open a session', slug: 'session' },
						{ label: 'Send commands', slug: 'commands' },
						{ label: 'BLE framing', slug: 'ble' },
						{ label: 'Host, ESP-IDF, Arduino', slug: 'platforms' },
					],
				},
			],
		}),
	],
});
