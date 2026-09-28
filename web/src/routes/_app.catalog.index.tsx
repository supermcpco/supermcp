import { useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Button, Input, Text } from "@cloudflare/kumo";
import { catalogListOptions } from "../api/@tanstack/react-query.gen";
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
      <div className="flex flex-wrap items-center gap-3">
        <div className="w-72">
          <Input aria-label="Search adapters" placeholder="Search" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={keyless} onChange={(e) => setKeyless(e.target.checked)} />
          <Text as="span">No credentials needed</Text>
        </label>
        <Text as="span" variant="secondary">
          {list.data ? `${list.data.count} adapters` : list.isPending ? "Loading…" : ""}
        </Text>
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
