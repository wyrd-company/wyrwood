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
  OpenBaoOK: boolean;
  OpenBaoURL: string;
  Controller: string;
  Notice: string;
  Problem: string;
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
export interface PolicyChoice {
  Name: string;
  Enforcement: string;
  Selected: boolean;
}
export interface ContainerRow {
  ID: string;
  Name: string;
  Image: string;
  State: string;
  KeyKind: string;
  Policy: string;
  Badge: string;
  BadgeClass: string;
  Bound: boolean;
  BindingID: string;
  KeyValue: string;
  Token: string;
  Checks: { Label: string; Mark: string; Status: string }[] | null;
  Candidates:
    | {
        Kind: string;
        Value: string;
        Note: string;
        Encoded: string;
        First: boolean;
      }[]
    | null;
}
export interface ContainersData extends Layout {
  Agents: { Name: string; Containers: number; Selected: boolean }[] | null;
  Agent: string;
  Connected: boolean;
  Rows: ContainerRow[] | null;
  Selected: ContainerRow | null;
  Policies: PolicyChoice[] | null;
  Recreate: string[] | null;
}
export interface ConfirmData extends Layout {
  Heading: string;
  Body: string;
  Action: string;
  Button: string;
  Danger: boolean;
  Back: string;
}
export interface PoliciesData extends Layout {
  Policies:
    | {
        Name: string;
        Revision: number;
        Enforcement: string;
        Bindings: number;
        Agents: number;
        SavedAt: string;
        SavedBy: string;
      }[]
    | null;
}
export interface PolicyData extends Layout {
  New: boolean;
  Name: string;
  Revision: number;
  Bindings: number;
  Agents: number;
  HCL: string;
  TokenTTL: string;
  TokenMaxTTL: string;
  TransitKeys: string;
  CARoles: string;
  NotForwardableTransitKeys: string;
  NotForwardableCARoles: string;
  MountTarget: string;
  Env: string;
  AccessGroup: string;
  Enforcement: string;
  Unpermitted: string[] | null;
  PolicyPath: string;
}
export interface KeysData extends Layout {
  TransitMount: string;
  SSHMount: string;
  Unavailable: boolean;
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
  containers: ContainersData;
  confirm: ConfirmData;
  policies: PoliciesData;
  policy: PolicyData;
  keys: KeysData;
  events: EventsData;
  security: SecurityData;
}
