'use strict';

const crypto = require('crypto');
const { Client } = require('ssh2');
const { Mutex } = require('async-mutex');

// OpenSSH-style fingerprint of a raw host key blob: "SHA256:<base64, no padding>"
// (same format as `ssh-keyscan host | ssh-keygen -lf -`).
function fingerprintOf(key) {
	return 'SHA256:' + crypto.createHash('sha256').update(key).digest('base64').replace(/=+$/, '');
}

module.exports = function (RED) {

	async function _connectClient(node, callback, failed = undefined){
		const release = await node.connectMutex.acquire();

		if(node.isConnected) {
			release();
			callback(node.client);
			return;
		};

		node.client = new Client();

		node.client.on('ready', () => {
			node.isConnected = true;
			node.log("Ssh client ready");
			node.status({ fill: "green", shape: "dot", text: 'Connected' });

			release();
			callback(node.client);
		});

		node.client.on('close', () => {
			node.isConnected = false;
			node.status({ fill: "red", shape: "dot", text: 'Disconnected' });
		});

		node.client.on('end', () => {
			node.isConnected = false;
			node.status({ fill: "red", shape: "dot", text: "Disconnected" });
		});

		node.client.on('error', (err) => {
			node.status({fill: "red", shape: "dot", text: err});
			node.log(err);
			release();
			node.isConnected = false;

			if(failed) {
				failed(err);
			};
		});

		node.client.on('continue', () => {
			if(node.continue) {
				node.continue();
			};
		});


		const pinned = (node.conf.fingerprint || '').trim();
		node.client.connect(Object.assign({}, node.conf.options, {
			// ssh2 auto-accepts any host key when hostVerifier is absent -> MITM.
			// Fail closed: no pinned fingerprint, no connection.
			hostVerifier: (key) => {
				const presented = fingerprintOf(key);
				if (!pinned) {
					node.error(`Host key not pinned for ${node.conf.options.host}; server presented ${presented}. Set it in the ssh-conf node after verifying it out of band.`);
					return false;
				}
				if (presented !== pinned) {
					node.error(`HOST KEY MISMATCH for ${node.conf.options.host}: expected ${pinned}, got ${presented}. Refusing to connect.`);
					return false;
				}
				return true;
			}
		}));
	};

	function SshConf(n) {
		RED.nodes.createNode(this,n);
		const node = this;
		node.fingerprint = n.fingerprint;
		let privateKey;
		if (n.ssh) {
			try {
				privateKey = require('fs').readFileSync(n.ssh);
			} catch (err) {
				node.error(`Cannot read private key ${n.ssh}: ${err.message}`);
			}
		}
		node.options = {
			host: node.credentials.hostname ? node.credentials.hostname : undefined,
			port: node.credentials.port ? node.credentials.port : undefined,
			username: node.credentials.username ? node.credentials.username : undefined,
			password: node.credentials.password ? node.credentials.password : undefined,
			privateKey: privateKey,
			passphrase: node.credentials.passphrase ? node.credentials.passphrase : undefined
		};
		node.connectMutex = new Mutex();
		node.sendMutex = new Mutex();

	};


	RED.nodes.registerType("ssh-conf",SshConf,{
		credentials: {
			username: { type: "text" },
			password: { type: "password" },
			passphrase: { type: "password" },
			hostname: { value: "" },
			port: { value: "" },
		}
	});




	function SshV3(config) {
		RED.nodes.createNode(this,config);
		this.conf = RED.nodes.getNode(config.conf);
		this.name = config.name;
		let node = this;
		node.connectMutex = new Mutex();
		node.sendMutex = new Mutex();


		node.status({ fill: "yellow", shape: "dot", text: "waiting for input" });

		node.on('input', async (msg, send, done) => {

			if (!msg.payload) {
				node.warn("msg.payload cant be empty");
				return;
			};
			if (typeof msg.payload != "string"){
				node.warn("msg.payload must be string");
				return;
			};

			const release = await node.sendMutex.acquire();

			const session = {
				code: 0,
				stdout: [],
				stderr: []
			};

			const notify = (type, data) => {
				switch (type) {
					case 0:
						session.code = data;
						msg.session = session;
						send(msg);
						done();
						break;
					case 1:
						session.stdout.push(data.toString());
						break;
					case 2:
						session.stderr.push(data.toString());
						break;
				}
			};

			await _connectClient(node, (conn) => {
				node.continue = () => {
					release();
				};

				const wait = conn.exec(msg.payload, (err, stream) => {
					// Was `throw err`: an uncaught exception that took down the whole
					// Node-RED process (issue #16). Fix from upstream PR #22 (alex2844).
					if (err) {
						node.error("Ssh client error on exec: " + err.message, msg);
						release();
						done(err);
						return;
					}

					stream.on('close', function (code, signal) {
						notify(0, code);
					}).on('data', (data) => {
						notify(1, data);
					}).stderr.on('data', (data) => {
						notify(2, data);
					});
				});

				if(wait) {
					node.continue = null;
					release();
				}
			}, (err) => {
				release();
				node.error(err, msg);
			});
			_connectClient(node, (conn) => { node.debug("SSH-CLI initial connection succeeded."); });
		});

		node.on('close', function () {
			node.client && node.client.end();
			node.client && node.client.destroy();
		});

		node.debug("SSH-CLI setup done.");
	}

	RED.nodes.registerType("ssh-v3",SshV3);

};
