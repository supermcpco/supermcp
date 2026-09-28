import { useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Button, Checkbox, Input, Text } from "@cloudflare/kumo";
import { catalogListOptions } from "../api/@tanstack/react-query.gen";
import { plural } from "../lib/analytics";
import { message } from "../lib/errors";
import { EmptyState } from "../components/form-dialog";

export const Route = createFileRoute("/_app/catalog/")({
  component: Catalog,
});

function Catalog() {
  const [q, setQ] = useState("");
  const [keyless, setKeyless] = useState(false);
  // The last answer stays on screen while the next search is asked, so the
  // list does not empty and refill on every keystroke.
  const list = useQuery({
    ...catalogListOptions({ query: { q: q || undefined, keyless: keyless || undefined } }),
    placeholderData: keepPreviousData,
  });
  const adapters = list.data?.adapters ?? [];

  return (
    <div className="grid gap-6">
      <div className="grid gap-1.5">
        <Text as="h1" variant="heading" size="lg">
          Catalog
        </Text>
        <Text>Install an adapter to create a connector with its tools.</Text>
      </div>
      {/* One row on a wide screen: the search at a readable width, the
          filter beside it, the count against the right edge. On a phone the
          search takes the whole line and the filter and count wrap under it. */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-3">
        <div className="w-full sm:max-w-md sm:flex-1">
          <Input
            type="search"
            className="w-full"
            aria-label="Search adapters"
            placeholder="Search"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        <Checkbox label="No credentials needed" checked={keyless} onCheckedChange={(checked) => setKeyless(checked)} />
        <span className="ml-auto">
          <Text as="span" variant="secondary" aria-live="polite">
            {list.data ? plural(list.data.count, "adapter") : list.isPending ? "Loading…" : ""}
          </Text>
        </span>
      </div>
      {list.isError && (
        <div role="alert">
          <Text>{message(list.error)}</Text>
        </div>
      )}
      {list.isSuccess && adapters.length === 0 && (
        <EmptyState
          title="No adapters match"
          action={
            <Button
              variant="primary"
              onClick={() => {
                setQ("");
                setKeyless(false);
              }}
            >
              Clear search
            </Button>
          }
        >
          Try other words, or clear the search to see every adapter.
        </EmptyState>
      )}
      <ul className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
        {adapters.map((a) => (
          <li key={a.slug} className="rounded-lg px-5 py-4 ring ring-kumo-line hover:bg-kumo-tint">
            <Link to="/catalog/$slug" params={{ slug: a.slug }} className="grid gap-1.5">
              <div className="flex items-baseline justify-between gap-2">
                <Text as="span" bold>
                  {a.name}
                </Text>
                <Text as="span" variant="secondary">
                  {a.toolCount} tools
                </Text>
              </div>
              <span className="line-clamp-2">
                <Text as="span" variant="secondary">
                  {a.description}
                </Text>
              </span>
              <div className="flex gap-2">
                <Badge>{a.category}</Badge>
                <Badge>{a.auth}</Badge>
                {a.keyless && <Badge>keyless</Badge>}
              </div>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Badge({ children }: { children: React.ReactNode }) {
  return (
    <span className="rounded-full bg-kumo-tint px-2 py-0.5 text-[12px] text-kumo-subtle ring ring-kumo-line">{children}</span>
  );
}
