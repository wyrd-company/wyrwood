// ---
// relationships:
//   implements: web-interface
// ---
// Keys match the existing Go page models. Navigation and form posts stay server-owned.
export interface Layout {
  Title: string;
  Current: string;
  CSRF: string;
  Operator: string;
  Pending: number;
  PendingOperatorKeys?: number;
  OpenBaoOK: boolean;
  OpenBaoURL: string;
  Controller: string;
  Notice: string;
  Problem: string;
  Tab?: string;
  ProblemTab?: string;
}
export interface SignInData extends Layout {
  Provider: string;
  IssuerHost: string;
  Version: string;
  Account: string;
}
export interface UpdateStatus {
  Enabled: boolean;
  Latest: string;
  Checked: string;
  LastSuccess: string;
  Unavailable: boolean;
}
export interface AgentsData extends Layout {
  Updates: UpdateStatus;
  UpdateAvailable: boolean;
  VersionComparable: boolean;
  Version: string;
  HostKey: string;
  PendingKeys:
    { Name: string; Fingerprint: string; FirstSeen: string }[] | null;
  Approved:
    | {
        Name: string;
        Version: string;
        OutOfDate: boolean;
        Connected: boolean;
        Containers: number;
        Bound: number;
        Health: { Category: string; Count: number }[] | null;
        LastReport: string;
      }[]
    | null;
}
export interface OperatorKeyRow {
  Label: string;
  Fingerprint: string;
  State: string;
  Agents: string[] | null;
  Policies: string[] | null;
  Actions: string[] | null;
  DecidedAt: string;
  DecidedBy: string;
  RevokedAt: string;
  RevokedBy: string;
  LastUsed: string;
}
export interface OperatorKeysData extends Layout {
  HostKey: string;
  PendingKeys:
    { Label: string; Fingerprint: string; FirstSeen: string }[] | null;
  Approved: OperatorKeyRow[] | null;
  Ended: OperatorKeyRow[] | null;
  GrantAgents: string[] | null;
  GrantPolicies: string[] | null;
}
export interface PolicyChoice {
  Name: string;
  Selected: boolean;
  Values?: string[] | null;
}
export interface AssignableGroups {
  groups: { gid: number; name?: string }[];
  any?: boolean;
}
export interface ContainerRow {
  AssignableGroups?: AssignableGroups | null;
  Screen: string;
  Agent: string;
  Connected: boolean;
  LastReport: string;
  Setup?: {
    Source: string;
    Target: string;
    Compose: string;
    DockerRun: string;
  } | null;
  ID: string;
  Name: string;
  Image: string;
  State: string;
  KeyKind: string;
  Policies: string[];
  Revision: number;
  Effective: EffectivePolicy;
  Settings: BindingSettings;
  Warnings: string[] | null;
  Applied: boolean;
  Badge: string;
  BadgeClass: string;
  Bound: boolean;
  BindingID: string;
  KeyValue: string;
  Directory?: string;
  Token: string;
  Checks: { Label: string; Mark: string; Status: string }[] | null;
  Candidates:
    | {
        Kind: string;
        Value: string;
        Note: string;
        Encoded: string;
      }[]
    | null;
}
export interface BindingRow {
  ID: string;
  Agent: string;
  AgentNotApproved: boolean;
  Connected: boolean;
  LastReport: string;
  KeyKind: string;
  KeyValue: string;
  Policies: string[] | null;
  Containers:
    | {
        ID: string;
        Name: string;
        Image: string;
        State: string;
        Screen: string;
      }[]
    | null;
  Badge: string;
  BadgeClass: string;
  Screen: string;
}
export interface ListData extends Layout {
  Agents: { Name: string; Count: number; Selected: boolean }[] | null;
  FilterAgent: string;
  Query: string;
  Sort: string;
  Order: string;
}
export interface BindingsData extends ListData {
  Rows: BindingRow[] | null;
  Add: string;
}
export interface AddBindingData extends ListData {
  Rows: ContainerRow[] | null;
  Back: string;
  TypedScreen: string;
}
export interface BindingForm {
  Key: string;
  Agent?: string;
  Directory?: string;
  Revision: number;
  Settings: EnteredBindingSettings;
  Understood: boolean;
}
export interface ConsumerStatus {
  directory?: string;
  "container-id"?: string;
  "access-group"?: number;
  sockets?: string[];
  failed?: string;
}
export interface BindingReadiness {
  readiness: "ready" | "waiting" | "failed" | "unknown";
  reasons?: string[];
  consumers: ConsumerStatus[];
  "last-error"?: string;
}
export interface BindingData extends Layout {
  Row: ContainerRow;
  Reported: boolean;
  Readiness?: BindingReadiness | null;
  Policies: PolicyChoice[] | null;
  Form: BindingForm;
  Typed?: boolean;
  AgentChoices?: { Name: string; Selected: boolean }[] | null;
  Screen: string;
  Action: string;
  Recreate: string;
  Unbind: string;
  Back: string;
}
export interface ConfirmData extends Layout {
  Heading: string;
  Body: string;
  Action: string;
  Button: string;
  Danger: boolean;
  Back: string;
}
export interface PolicyDeleteData extends ConfirmData {
  Blockers: BindingRow[] | null;
}
export interface PolicyRenameData extends Layout {
  Name: string;
  NewName: string;
  Revision: number;
  Generation: number;
  Identity: string;
  Consequence: string;
  Action: string;
  Back: string;
  Bindings: BindingRow[] | null;
}
export interface PoliciesData extends Layout {
  Policies:
    | {
        Name: string;
        Revision: number;
        Bindings: number;
        Agents: number;
        SavedAt: string;
        SavedBy: string;
      }[]
    | null;
}
export interface PolicyData extends Layout {
  AgentTokenRenewal: boolean;
  KVMounts: string[] | null;
  AvailableTransitKeys: string[] | null;
  AvailableCARoles: string[] | null;
  IdentityProblems: string[] | null;
  Warnings: string[] | null;
  New: boolean;
  Name: string;
  Revision: number;
  BindingRows: BindingRow[] | null;
  Bindings: number;
  Agents: number;
  HCL: string;
  TransitKeys: string;
  CARoles: string;
  NotForwardableTransitKeys: string;
  NotForwardableCARoles: string;
  MountTarget: string;
  Env: string;
  Unpermitted: string[] | null;
  PolicyPath: string;
}
export interface KeysData extends Layout {
  TransitMount: string;
  SSHMount: string;
  Problems: string[] | null;
  Transit:
    | {
        Name: string;
        Type: string;
        Version: number;
        Fingerprint: string;
        UsedBy: string[] | null;
      }[]
    | null;
  Roles:
    | {
        Name: string;
        AllowedUsers: string;
        TTL: string;
        UsedBy: string[] | null;
      }[]
    | null;
}
export interface EventsData extends Layout {
  Outcome: string;
  Outcomes: string[];
  Events:
    | {
        Time: string;
        Operation: string;
        Outcome: string;
        Error: string;
        Class: string;
        Subject: string;
        Operator: string;
        Latency: string;
      }[]
    | null;
}
export interface SecurityData extends Layout {
  Email: string;
  Name: string;
  AdmittedGroup: string;
  AllowedGroups: string[];
  Provider: string;
  Issuer: string;
  ClientID: string;
  RedirectURL: string;
  Reachable: boolean;
  Fetched: string;
  Sessions: { Current: boolean; CreatedAt: string; ExpiresAt: string }[] | null;
}
export type Page = {
  [K in keyof PageModels]: { page: K; data: PageModels[K] };
}[keyof PageModels];
interface PageModels {
  "sign-in": SignInData;
  agents: AgentsData;
  bindings: BindingsData;
  "add-binding": AddBindingData;
  binding: BindingData;
  confirm: ConfirmData;
  "policy-delete": PolicyDeleteData;
  "policy-rename": PolicyRenameData;
  policies: PoliciesData;
  policy: PolicyData;
  keys: KeysData;
  "operator-keys": OperatorKeysData;
  events: EventsData;
  security: SecurityData;
  settings: SettingsData;
}

export interface BindingSettings {
  "token-ttl": string;
  "token-max-ttl": string;
  "access-group"?: number;
  enforcement: "report" | "recreate";
}
export interface EnteredBindingSettings {
  values?: Record<string, string>;
  "token-ttl"?: string;
  "token-max-ttl"?: string;
  "access-group"?: number | string;
  enforcement?: string;
}
export interface EffectivePolicy {
  sources: { name: string; revision: number; hcl: string }[];
  openbao: { policy: string; "agent-token-renewal"?: boolean };
  ssh?: {
    "transit-keys"?: string[];
    "ca-roles"?: string[];
    "not-forwardable"?: { "transit-keys"?: string[]; "ca-roles"?: string[] };
  };
  contract: {
    "mount-target": string;
    env?: Record<string, string>;
    "access-group"?: number;
    enforcement: string;
  };
  settings: BindingSettings;
}

export interface SettingsData extends Layout {
  Sections: { Title: string; Settings: { Label: string; Value: string }[] }[];
}
