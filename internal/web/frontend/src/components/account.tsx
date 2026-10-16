// ---
// relationships:
//   implements: web-interface
// ---
import { Button, CSRF } from "./shared";
import { useId } from "react";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
} from "./ui/dropdown-menu";
import type { Layout } from "@/types";
export function Account({ data }: { data: Layout }) {
  const signOutForm = useId();
  return (
    <>
      <form id={signOutForm} method="post" action="/sign-out" hidden>
        <CSRF token={data.CSRF} />
      </form>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" className="account-trigger">
            <span className="account-identity">
              <span className="account-label">Account</span>
              <span className="account-operator">{data.Operator}</span>
            </span>
            <svg
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              aria-hidden="true"
            >
              <path d="m6 15 6-6 6 6" />
            </svg>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent
          side="top"
          align="start"
          sideOffset={8}
          collisionPadding={8}
          className="w-(--radix-dropdown-menu-trigger-width) min-w-48"
        >
          <DropdownMenuItem asChild>
            <a
              href="/security"
              aria-current={data.Current === "security" ? "page" : undefined}
            >
              Security
            </a>
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem asChild>
            <button
              type="submit"
              form={signOutForm}
              className="w-full text-left"
            >
              Sign out
            </button>
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </>
  );
}
