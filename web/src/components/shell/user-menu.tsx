import { useNavigate } from "@tanstack/react-router";
import { hashKey, useMutation, useQueryClient } from "@tanstack/react-query";
import { DropdownMenu, Text, useSidebar } from "@cloudflare/kumo";
import { CaretUpDown, GearSix, SignOut } from "@phosphor-icons/react";
import { logoutMutation, sessionQueryKey } from "../../api/@tanstack/react-query.gen";
import { useRefreshSession, useSession } from "../../lib/session";
import { message } from "../../lib/errors";
import { toast } from "./toast";
import { initials } from "./initials";
import { NamedTooltip, TruncatedText } from "./named-tooltip";

/**
 * Who is signed in, in which workspace, and the way out, as one button at
 * the foot of the sidebar that opens a menu. Somebody sharing a machine
 * needs that last part, and a product that can only be left by clearing
 * cookies is a product that keeps sessions it should not.
 *
 * It only renders inside the signed-in layout, whose guard has already
 * made sure there is a session.
 */
export function UserMenu() {
  const { session } = useSession();
  const { state, isMobile } = useSidebar();
  const rail = state === "collapsed" && !isMobile;
  const navigate = useNavigate();
  const qc = useQueryClient();
  const refresh = useRefreshSession();
  const signOut = useMutation({
    ...logoutMutation(),
    onSuccess: async () => {
      // Off the console first, so nothing under it renders against a
      // session that has ended; then drop everything the last person could
      // see, and ask again who (nobody) is here.
      await navigate({ to: "/login", search: {} });
      const current = hashKey(sessionQueryKey());
      qc.removeQueries({ predicate: (q) => q.queryHash !== current });
      await refresh();
      toast("You have signed out.");
    },
    onError: (e) => toast(message(e), { kind: "error" }),
  });

  const email = session?.user?.email ?? "";
  const name = session?.user?.name?.trim() || undefined;
  const who = name ?? email;
  const workspace = session?.organization?.name ?? "No workspace";
  return (
    <DropdownMenu>
      {/* On the rail only the badge is left, so it names the person in a
          tooltip; expanded, the button says it itself. */}
      <NamedTooltip
        label={email}
        side="right"
        disabled={!rail}
        render={
          <DropdownMenu.Trigger
            render={
              <button
                type="button"
                // Expanded, the button is named by what it shows; on the rail
                // that text is gone, so it is named in words instead.
                aria-label={rail ? `${who}, ${workspace}` : undefined}
                className="flex min-w-0 flex-1 cursor-pointer items-center gap-2.5 rounded-lg py-1 pr-2 pl-1.5 text-left text-kumo-default outline-none hover:bg-(--sidebar-active-bg) focus-visible:bg-(--sidebar-active-bg) focus-visible:ring-2 focus-visible:ring-kumo-brand data-[popup-open]:bg-(--sidebar-active-bg) group-data-[state=collapsed]/sidebar:w-8.5 group-data-[state=collapsed]/sidebar:flex-none group-data-[state=collapsed]/sidebar:px-[3px]"
              />
            }
          />
        }
      >
        <span
          aria-hidden
          className="grid size-7 shrink-0 place-items-center rounded-full bg-kumo-tint text-xs font-semibold text-kumo-default"
        >
          {initials(name, email)}
        </span>
        <span className="grid min-w-0 flex-1 leading-4 group-data-[state=collapsed]/sidebar:hidden">
          <TruncatedText text={who}>
            <Text as="span" size="sm" bold>
              {who}
            </Text>
          </TruncatedText>
          <TruncatedText text={workspace}>
            <Text as="span" size="xs" variant="secondary">
              {workspace}
            </Text>
          </TruncatedText>
        </span>
        <CaretUpDown size={14} aria-hidden className="shrink-0 text-kumo-subtle group-data-[state=collapsed]/sidebar:hidden" />
      </NamedTooltip>
      <DropdownMenu.Content side={rail ? "right" : "top"} align={rail ? "end" : "start"} className="min-w-56">
        <DropdownMenu.Group>
          <DropdownMenu.Label className="grid font-normal">
            {name && (
              <Text as="span" size="sm" bold>
                {name}
              </Text>
            )}
            <Text as="span" size="sm" variant="secondary">
              {email}
            </Text>
          </DropdownMenu.Label>
        </DropdownMenu.Group>
        <DropdownMenu.Item href="/settings/security" icon={GearSix}>
          Account settings
        </DropdownMenu.Item>
        <DropdownMenu.Separator />
        <DropdownMenu.Item icon={SignOut} onClick={() => signOut.mutate({})} disabled={signOut.isPending}>
          Sign out
        </DropdownMenu.Item>
      </DropdownMenu.Content>
    </DropdownMenu>
  );
}
