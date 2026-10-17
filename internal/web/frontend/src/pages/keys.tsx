// ---
// relationships:
//   implements: web-interface
// ---
import {
  Button,
  CSRF,
  Field,
  Input,
  Notice,
  PolicyLinks,
  Table,
} from "@/components/shared";
import { DurationPicker } from "@/components/duration-picker";
import type { KeysData } from "@/types";
export function Keys({ data: d }: { data: KeysData }) {
  return (
    <main>
      <Notice text={d.Notice} />
      {d.Unavailable && (
        <p className="caution" role="alert">
          OpenBao did not answer. The lists below may be incomplete; agents keep
          serving containers.
        </p>
      )}
      <section className="flex flex-col gap-3" aria-labelledby="h-tr">
        <div className="section-head">
          <div>
            <h2 id="h-tr">Transit keys</h2>
            <span className="sub">
              Mount <code>{d.TransitMount}</code> · private keys never leave
              OpenBao
            </span>
          </div>
        </div>
        <Table
          columns={["Name", "Type", "Version", "SSH fingerprint", "Used by"]}
          count={d.Transit?.length ?? 0}
          empty="No Transit keys."
        >
          {d.Transit?.map((key) => (
            <tr key={key.Name}>
              <th scope="row" className="mono">
                {key.Name}
              </th>
              <td>{key.Type}</td>
              <td>
                {key.Version}{" "}
                <form
                  className="inline"
                  method="post"
                  action="/keys/transit/rotate"
                >
                  <CSRF token={d.CSRF} />
                  <input type="hidden" name="name" value={key.Name} />
                  <Button variant="outline" type="submit" className="small">
                    Rotate
                  </Button>
                </form>
              </td>
              <td className="mono text-xs">
                {key.Fingerprint || (
                  <span className="hint">not a signing key</span>
                )}
              </td>
              <td>
                <PolicyLinks names={key.UsedBy} />
              </td>
            </tr>
          ))}
        </Table>
        <form method="post" action="/keys/transit" className="card key-form">
          <CSRF token={d.CSRF} />
          <Field label="New Transit key" id="key-name">
            <Input id="key-name" name="name" type="text" required />
          </Field>
          <Field label="Type" id="key-type">
            <select id="key-type" name="type">
              {["ed25519", "rsa-2048", "rsa-3072", "rsa-4096"].map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
            </select>
          </Field>
          <Button type="submit" className="primary">
            Create key
          </Button>
        </form>
      </section>
      <section className="flex flex-col gap-3" aria-labelledby="h-ssh">
        <div className="section-head">
          <div>
            <h2 id="h-ssh">SSH-engine roles</h2>
            <span className="sub">
              Mount <code>{d.SSHMount}</code> · certificates issued under each
              container's own token
            </span>
          </div>
        </div>
        <Table
          columns={["Role", "Allowed users", "Certificate TTL", "Used by"]}
          count={d.Roles?.length ?? 0}
          empty="No SSH roles."
        >
          {d.Roles?.map((role) => (
            <tr key={role.Name}>
              <th scope="row" className="mono">
                {role.Name}
              </th>
              <td>{role.AllowedUsers}</td>
              <td>{role.TTL}</td>
              <td>
                <PolicyLinks names={role.UsedBy} />
              </td>
            </tr>
          ))}
        </Table>
        <form method="post" action="/keys/ssh" className="card key-form">
          <CSRF token={d.CSRF} />
          <Field label="New SSH role" id="role-name">
            <Input id="role-name" name="name" type="text" required />
          </Field>
          <Field label="Allowed users" id="role-users">
            <Input
              id="role-users"
              name="allowed-users"
              type="text"
              placeholder="git,deploy"
              required
            />
          </Field>
          <Field label="TTL" id="role-ttl">
            <DurationPicker id="role-ttl" name="ttl" value="30m" />
          </Field>
          <Button type="submit" className="primary">
            Create role
          </Button>
        </form>
      </section>
      <p className="hint">
        Only mounts named in the controller configuration are listed. Wyrwood
        never reads secret values; the policy editor lists KV metadata paths.
      </p>
    </main>
  );
}
