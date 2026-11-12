-- Controller state written by the store at commit 93b53c4ae8ca5c082318d16b978d95532416230c
-- (schema 4, Wyrwood 0.6.1 plus the epic), dumped with sqlite3 .dump. Do not edit.
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE agents (
		fingerprint TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		public_key TEXT NOT NULL,
		state TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'rejected')),
		first_seen INTEGER NOT NULL,
		decided_at INTEGER,
		decided_by TEXT NOT NULL DEFAULT '',
		agent_version TEXT NOT NULL DEFAULT '',
		allow_recreate INTEGER NOT NULL DEFAULT 0,
		last_connected INTEGER,
		last_report INTEGER
	);
INSERT INTO agents VALUES('SHA256:agent-a','host-a','ssh-ed25519 AAAAagent','approved',1700000001000000000,1700000002000000000,'operator-1','',0,NULL,1700000021000000000);
INSERT INTO agents VALUES('SHA256:agent-b','host-b','ssh-ed25519 AAAApending','pending',1700000003000000000,NULL,'','',0,NULL,NULL);
CREATE TABLE policies (
		name TEXT PRIMARY KEY,
		revision INTEGER NOT NULL,
		document TEXT NOT NULL,
		saved_at INTEGER NOT NULL,
		saved_by TEXT NOT NULL DEFAULT ''
	, generation INTEGER NOT NULL DEFAULT 1 CHECK (generation >= 1));
INSERT INTO policies VALUES('sample',1,'{"name":"sample","revision":1,"openbao":{"policy":"","agent-token-renewal":true},"contract":{"mount-target":"/run/wyrwood","env":{"SSH_AUTH_SOCK":"{mount-target}/ssh-agent.sock","VAULT_ADDR":"unix://{mount-target}/vault.sock"}}}',1700000004000000000,'operator-1',1);
INSERT INTO policies VALUES('unused',1,'{"name":"unused","revision":1,"openbao":{"policy":"","agent-token-renewal":true},"contract":{"mount-target":"/run/wyrwood","env":{"SSH_AUTH_SOCK":"{mount-target}/ssh-agent.sock","VAULT_ADDR":"unix://{mount-target}/vault.sock"}}}',1700000005000000000,'operator-1',1);
CREATE TABLE bindings (
		id TEXT PRIMARY KEY,
		agent TEXT NOT NULL,
		key_kind TEXT NOT NULL,
		key_value TEXT NOT NULL,
		settings TEXT NOT NULL,
        revision INTEGER NOT NULL,
        effective TEXT NOT NULL,
        applied INTEGER NOT NULL DEFAULT 0,
		role TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		created_by TEXT NOT NULL DEFAULT '',
		UNIQUE (agent, key_kind, key_value)
	);
INSERT INTO bindings VALUES('b-name','host-a','name','web','{"token-ttl":"1h","token-max-ttl":"8h","enforcement":"report"}',1,'{"sources":[{"name":"sample","revision":1,"hcl":""}],"openbao":{"policy":"# Policy sample (revision 1)\n\npath \"auth/token/lookup-self\" { capabilities = [\"read\"] }\npath \"auth/token/renew-self\" { capabilities = [\"update\"] }\npath \"auth/token/revoke-self\" { capabilities = [\"update\"] }\n\n","agent-token-renewal":true},"ssh":{"not-forwardable":{}},"contract":{"mount-target":"/run/wyrwood","env":{"SSH_AUTH_SOCK":"/run/wyrwood/ssh-agent.sock","VAULT_ADDR":"unix:///run/wyrwood/vault.sock"},"enforcement":"report"},"settings":{"token-ttl":"1h","token-max-ttl":"8h","enforcement":"report"}}',1,'wyrwood-host-a-b-name',1700000010000000000,'operator-1');
INSERT INTO bindings VALUES('b-compose','host-a','compose','shop/api','{"token-ttl":"1h","token-max-ttl":"8h","enforcement":"report"}',1,'{"sources":[{"name":"sample","revision":1,"hcl":""}],"openbao":{"policy":"# Policy sample (revision 1)\n\npath \"auth/token/lookup-self\" { capabilities = [\"read\"] }\npath \"auth/token/renew-self\" { capabilities = [\"update\"] }\npath \"auth/token/revoke-self\" { capabilities = [\"update\"] }\n\n","agent-token-renewal":true},"ssh":{"not-forwardable":{}},"contract":{"mount-target":"/run/wyrwood","env":{"SSH_AUTH_SOCK":"/run/wyrwood/ssh-agent.sock","VAULT_ADDR":"unix:///run/wyrwood/vault.sock"},"enforcement":"report"},"settings":{"token-ttl":"1h","token-max-ttl":"8h","enforcement":"report"}}',1,'wyrwood-host-a-b-compose',1700000011000000000,'operator-1');
INSERT INTO bindings VALUES('b-devcontainer','host-a','devcontainer','/src/app','{"token-ttl":"1h","token-max-ttl":"8h","enforcement":"report"}',1,'{"sources":[{"name":"sample","revision":1,"hcl":""}],"openbao":{"policy":"# Policy sample (revision 1)\n\npath \"auth/token/lookup-self\" { capabilities = [\"read\"] }\npath \"auth/token/renew-self\" { capabilities = [\"update\"] }\npath \"auth/token/revoke-self\" { capabilities = [\"update\"] }\n\n","agent-token-renewal":true},"ssh":{"not-forwardable":{}},"contract":{"mount-target":"/run/wyrwood","env":{"SSH_AUTH_SOCK":"/run/wyrwood/ssh-agent.sock","VAULT_ADDR":"unix:///run/wyrwood/vault.sock"},"enforcement":"report"},"settings":{"token-ttl":"1h","token-max-ttl":"8h","enforcement":"report"}}',1,'wyrwood-host-a-b-devcontainer',1700000012000000000,'operator-1');
CREATE TABLE binding_policies (
        binding_id TEXT NOT NULL REFERENCES bindings(id) ON DELETE CASCADE,
        policy_name TEXT NOT NULL REFERENCES policies(name),
        PRIMARY KEY(binding_id, policy_name)
    );
INSERT INTO binding_policies VALUES('b-name','sample');
INSERT INTO binding_policies VALUES('b-compose','sample');
INSERT INTO binding_policies VALUES('b-devcontainer','sample');
CREATE TABLE inventories (
		agent TEXT PRIMARY KEY,
		containers TEXT NOT NULL,
		reported_at INTEGER NOT NULL
	);
INSERT INTO inventories VALUES('host-a','[{"id":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","name":"web","state":"running","consumer-directory":"/run/wyrwood/containers/web","keys":[{"kind":"name","value":"web"}]}]',1700000021000000000);
CREATE TABLE retired_bindings (
		id TEXT PRIMARY KEY,
		agent TEXT NOT NULL,
		retired_at INTEGER NOT NULL
	);
INSERT INTO retired_bindings VALUES('b-gone','host-a',1700000020000000000);
CREATE TABLE binding_tokens (
		binding TEXT PRIMARY KEY REFERENCES bindings(id) ON DELETE CASCADE,
		accessor TEXT NOT NULL,
		updated_at INTEGER NOT NULL
	);
INSERT INTO binding_tokens VALUES('b-name','accessor-1',1700000022000000000);
CREATE TABLE contract_results (
		binding TEXT PRIMARY KEY REFERENCES bindings(id) ON DELETE CASCADE,
		outcome TEXT NOT NULL,
		failed_items TEXT NOT NULL,
		container_id TEXT NOT NULL DEFAULT '',
		reason TEXT NOT NULL DEFAULT '',
		updated_at INTEGER NOT NULL
	);
INSERT INTO contract_results VALUES('b-name','conforming','null','','',1700000023000000000);
CREATE TABLE operators (
		subject TEXT PRIMARY KEY,
		display_name TEXT NOT NULL,
		email TEXT NOT NULL,
		last_sign_in INTEGER NOT NULL
	);
INSERT INTO operators VALUES('subject-1','Operator One','operator@example.invalid',1700000024000000000);
CREATE TABLE web_sessions (
		id_hash TEXT PRIMARY KEY,
		subject TEXT NOT NULL REFERENCES operators(subject),
		admitted_group TEXT NOT NULL,
		csrf TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL
	);
INSERT INTO web_sessions VALUES('hash-1','subject-1','operators','csrf-1',1700000025000000000,1700000026000000000);
CREATE TABLE policy_generations (
		name TEXT PRIMARY KEY,
		generation INTEGER NOT NULL CHECK (generation >= 1)
	);
INSERT INTO policy_generations VALUES('sample',1);
INSERT INTO policy_generations VALUES('unused',1);
CREATE TABLE policy_retirements (
		identity TEXT PRIMARY KEY,
		recorded_at INTEGER NOT NULL
	);
INSERT INTO policy_retirements VALUES('wyrwood-retired',1700000006000000000);
CREATE TABLE operator_keys (
		fingerprint TEXT PRIMARY KEY,
		label TEXT NOT NULL,
		public_key TEXT NOT NULL,
		state TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'rejected', 'revoked')),
		grants TEXT NOT NULL DEFAULT '{}',
		first_seen INTEGER NOT NULL,
		decided_at INTEGER,
		decided_by TEXT NOT NULL DEFAULT '',
		revoked_at INTEGER,
		revoked_by TEXT NOT NULL DEFAULT '',
		last_used INTEGER
	);
INSERT INTO operator_keys VALUES('SHA256:operator-key','sample-key','ssh-ed25519 AAAAoperator','approved','{"agents":["host-a"],"policies":["sample"],"actions":["read","bind"]}',1700000027000000000,1700000028000000000,'operator-1',NULL,'',NULL);
CREATE UNIQUE INDEX agents_approved_name ON agents(name) WHERE state = 'approved';
CREATE UNIQUE INDEX operator_keys_label ON operator_keys(label) WHERE state IN ('approved', 'revoked');
COMMIT;
PRAGMA user_version = 4;
