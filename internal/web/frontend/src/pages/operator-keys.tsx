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
  Panel,
  Status,
  Table,
} from "@/components/shared";
import { ago, stamp } from "@/lib/time";
import type { OperatorKeyRow, OperatorKeysData } from "@/types";
import { GrantChoices } from "./operator-key-grant";

function names(list: string[] | null) {
  if (!list?.length) return <span className="hint">none</span>;
  if (list.length === 1 && list[0] === "*") return <>all</>;
  return <>{list.join(", ")}</>;
}

function never(time: string) {
  return !time || time.startsWith("0001-");
}

function When({ time }: { time: string }) {
  if (never(time)) return <span className="hint">never</span>;
  return (
    <time dateTime={time} title={stamp(time)}>
      {ago(time)}
    </time>
  );
}

function PendingKey({
  fingerprint,
  label,
  firstSeen,
  csrf,
  agents,
  policies,
}: {
  fingerprint: string;
  label: string;
  firstSeen: string;
  csrf: string;
  agents: string[];
  policies: string[];
}) {
  const id = fingerprint.replace(/[^A-Za-z0-9]/g, "");
  return (
    <Panel className="flex flex-col gap-3">
      <div className="min-w-0">
        <div>
          <strong>{label}</strong>{" "}
          <span className="hint">
            presented label · first seen {ago(firstSeen)}
          </span>
        </div>
        <code className="break-all">{fingerprint}</code>
        <p className="hint">
          Approve only if this matches the fingerprint printed by{" "}
          <code>wyrwood operator login</code>. An operator key acts without a
          sign-in, for as long as it is not revoked.
        </p>
      </div>
      <form method="post" action="/operator-keys/approve">
        <CSRF token={csrf} />
        <input type="hidden" name="fingerprint" value={fingerprint} />
        <Field
          label="Label"
          id={`label-${id}`}
          hint="Events name this key by this label. It stays with this key."
        >
          <Input
            id={`label-${id}`}
            name="label"
            type="text"
            defaultValue={label}
            required
            pattern="[A-Za-z0-9][A-Za-z0-9._\-]*"
            maxLength={64}
          />
        </Field>
        <GrantChoices id={id} agents={agents} policies={policies} />
        <div className="actions">
          <Button type="submit" className="primary">
            Approve key
          </Button>
          <Button
            variant="outline"
            type="submit"
            formAction="/operator-keys/reject"
            formNoValidate
            className="danger"
          >
            Reject
          </Button>
        </div>
      </form>
    </Panel>
  );
}

function KeyCells({ item }: { item: OperatorKeyRow }) {
  return (
    <>
      <th scope="row">
        {item.Label}
        <br />
        <code className="break-all hint">{item.Fingerprint}</code>
      </th>
      <td>{names(item.Agents)}</td>
      <td>{names(item.Policies)}</td>
      <td>{names(item.Actions)}</td>
    </>
  );
}

export function OperatorKeys({ data: d }: { data: OperatorKeysData }) {
  return (
    <main>
      <Notice text={d.Notice} />
      <Panel aria-labelledby="h-operator-hk">
        <div className="section-head">
          <div>
            <h2 id="h-operator-hk" className="hint">
              Controller SSH host key
            </h2>
            <code className="break-all">{d.HostKey}</code>
          </div>
          <p className="hint max-w-sm">
            An operator key manages policies and bindings from a script, inside
            its grant. It is not an agent key. Run{" "}
            <code>wyrwood operator login</code> on the machine that holds it.
          </p>
        </div>
      </Panel>
      {!!d.PendingKeys?.length && (
        <section aria-labelledby="h-op-pend" className="flex flex-col gap-3">
          <div className="section-head">
            <h2 id="h-op-pend">Pending operator keys</h2>
            <span className="sub">
              {d.PendingKeys.length} key{d.PendingKeys.length > 1 && "s"}
            </span>
          </div>
          {d.PendingKeys.map((key) => (
            <PendingKey
              key={key.Fingerprint}
              fingerprint={key.Fingerprint}
              label={key.Label}
              firstSeen={key.FirstSeen}
              csrf={d.CSRF}
              agents={d.GrantAgents ?? []}
              policies={d.GrantPolicies ?? []}
            />
          ))}
        </section>
      )}
      <section aria-labelledby="h-op-appr" className="flex flex-col gap-3">
        <h2 id="h-op-appr">Approved operator keys</h2>
        {d.Approved?.length ? (
          <Table
            columns={[
              "Key",
              "Agents",
              "Policies",
              "Actions",
              "Approved by",
              "Last used",
              "",
            ]}
            count={d.Approved.length}
            empty=""
          >
            {d.Approved.map((item) => (
              <tr key={item.Fingerprint}>
                <KeyCells item={item} />
                <td>{item.DecidedBy}</td>
                <td>
                  <When time={item.LastUsed} />
                </td>
                <td>
                  <Button asChild variant="outline" className="danger">
                    <a
                      href={`/operator-keys/revoke?fingerprint=${encodeURIComponent(item.Fingerprint)}`}
                    >
                      Revoke {item.Label}
                    </a>
                  </Button>
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <p className="hint">No operator key is approved.</p>
        )}
      </section>
      {!!d.Ended?.length && (
        <section aria-labelledby="h-op-ended" className="flex flex-col gap-3">
          <h2 id="h-op-ended">Revoked and rejected keys</h2>
          <Table
            columns={["Key", "Agents", "Policies", "Actions", "State", "By"]}
            count={d.Ended.length}
            empty=""
          >
            {d.Ended.map((item) => (
              <tr key={item.Fingerprint}>
                <KeyCells item={item} />
                <td>
                  <Status kind="denied">{item.State}</Status>
                </td>
                <td>{item.RevokedBy || item.DecidedBy}</td>
              </tr>
            ))}
          </Table>
        </section>
      )}
    </main>
  );
}
