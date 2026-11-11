// ---
// relationships:
//   verifies: web-interface
// ---
import { describe, expect, it } from "vitest";
import {
  type GrantAction,
  grantActions,
  grantNames,
  summarizeGrant,
} from "./grant-summary";

interface Lists {
  name: string;
  agents: string[];
  policies: string[];
  allowed: Record<GrantAction, string>;
}

// Each list shape states the allowed line of every action. The denied lines
// are the same for every shape.
const shapes: Lists[] = [
  {
    name: "one agent and one policy",
    agents: ["agent-a"],
    policies: ["policy-x"],
    allowed: {
      read: "Can read policy-x, and bindings on agent-a that hold no policy other than policy-x.",
      bind: "Can create and remove bindings on agent-a that hold no policy other than policy-x.",
      "policy-write":
        "Can create and change policy-x, when every binding that holds the policy is on agent-a and holds no policy other than policy-x.",
    },
  },
  {
    name: "several names",
    agents: ["agent-a", "agent-b", "agent-c"],
    policies: ["policy-x", "policy-y"],
    allowed: {
      read: "Can read policy-x and policy-y, and bindings on agent-a, agent-b, and agent-c that hold no policy other than policy-x and policy-y.",
      bind: "Can create and remove bindings on agent-a, agent-b, and agent-c that hold no policy other than policy-x and policy-y.",
      "policy-write":
        "Can create and change policy-x and policy-y, when every binding that holds the policy is on agent-a, agent-b, and agent-c and holds no policy other than policy-x and policy-y.",
    },
  },
  {
    name: "* for both lists",
    agents: ["*"],
    policies: ["*"],
    allowed: {
      read: "Can read every policy, and every binding.",
      bind: "Can create and remove every binding.",
      "policy-write": "Can create and change every policy.",
    },
  },
  {
    name: "* for agents and a named policy",
    agents: ["*"],
    policies: ["policy-x"],
    allowed: {
      read: "Can read policy-x, and bindings on every agent that hold no policy other than policy-x.",
      bind: "Can create and remove bindings on every agent that hold no policy other than policy-x.",
      "policy-write":
        "Can create and change policy-x, when every binding that holds the policy holds no policy other than policy-x.",
    },
  },
  {
    name: "a named agent and * for policies",
    agents: ["agent-a"],
    policies: ["*"],
    allowed: {
      read: "Can read every policy, and bindings on agent-a.",
      bind: "Can create and remove bindings on agent-a.",
      "policy-write":
        "Can create and change every policy, when every binding that holds the policy is on agent-a.",
    },
  },
];

const denied: Record<GrantAction, string> = {
  read: "Cannot read policies or bindings.",
  bind: "Cannot bind or unbind.",
  "policy-write": "Cannot change policies.",
};

// Every subset of the three actions, the empty one included.
const combinations = Array.from({ length: 8 }, (_, mask) =>
  grantActions.filter((_, index) => mask & (1 << index)),
);

describe("summarizeGrant", () => {
  const table = shapes.flatMap((shape) =>
    combinations.map((actions) => ({ ...shape, actions })),
  );
  it.each(table)(
    "$name with actions $actions states each action",
    ({ agents, policies, allowed, actions }) => {
      const summary = summarizeGrant({ agents, policies, actions });
      expect(summary.refusals).toEqual(
        actions.length
          ? []
          : ["Approval is refused: select at least one action."],
      );
      expect(summary.lines.map((line) => line.action)).toEqual(grantActions);
      for (const line of summary.lines) {
        const can = actions.includes(line.action);
        expect(line.allowed).toBe(can);
        expect(line.text).toBe(
          can ? allowed[line.action] : denied[line.action],
        );
        expect(line.text.startsWith("Can ")).toBe(can);
      }
    },
  );

  it.each([
    {
      name: "no agent",
      agents: [],
      policies: ["policy-x"],
      lines: [
        [
          true,
          "Can read policy-x. Cannot read bindings: no agent is selected.",
        ],
        [false, "Cannot bind or unbind: no agent is selected."],
        [
          true,
          "Can create and change policy-x, when no binding holds the policy.",
        ],
      ],
    },
    {
      name: "no policy",
      agents: ["agent-a"],
      policies: [],
      lines: [
        [false, "Cannot read policies or bindings: no policy is selected."],
        [false, "Cannot bind or unbind: no policy is selected."],
        [false, "Cannot change policies: no policy is selected."],
      ],
    },
    {
      name: "neither list",
      agents: [],
      policies: [],
      lines: [
        [false, "Cannot read policies or bindings: no policy is selected."],
        [false, "Cannot bind or unbind: no agent is selected."],
        [false, "Cannot change policies: no policy is selected."],
      ],
    },
  ])(
    "states an empty list as nothing: $name",
    ({ agents, policies, lines }) => {
      const summary = summarizeGrant({
        agents,
        policies,
        actions: [...grantActions],
      });
      expect(summary.refusals).toEqual([]);
      expect(summary.lines.map((line) => [line.allowed, line.text])).toEqual(
        lines,
      );
    },
  );

  it.each([
    { agents: ["*", "agent-a"], policies: ["policy-x"], what: "agents" },
    { agents: ["agent-a"], policies: ["policy-x", "*"], what: "policies" },
  ])("refuses * with names in the $what list", ({ agents, policies, what }) => {
    const summary = summarizeGrant({
      agents,
      policies,
      actions: [...grantActions],
    });
    expect(summary.refusals).toEqual([
      `Approval is refused: the ${what} list holds * and names. Use * alone, or names alone.`,
    ]);
    expect(summary.lines.map((line) => [line.allowed, line.text])).toEqual(
      grantActions.map((action) => [false, denied[action]]),
    );
  });

  it("names a repeated name once", () => {
    const summary = summarizeGrant({
      agents: ["agent-a", "agent-a"],
      policies: ["policy-x"],
      actions: ["bind"],
    });
    expect(summary.lines[1].text).toBe(
      "Can create and remove bindings on agent-a that hold no policy other than policy-x.",
    );
  });
});

describe("grantNames", () => {
  it("separates names as the server does", () => {
    expect(grantNames(" agent-a,agent-b\n agent-c ,,\tagent-d\r")).toEqual([
      "agent-a",
      "agent-b",
      "agent-c",
      "agent-d",
    ]);
    expect(grantNames("  ")).toEqual([]);
  });
});
