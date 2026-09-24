import { useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Input, Text } from "@cloudflare/kumo";
import { catalogListOptions } from "../api/@tanstack/react-query.gen";

export const Route = createFileRoute("/catalog/")({
  component: Catalog,
});

function Catalog() {
  const [q, setQ] = useState("");
  const [keyless, setKeyless] = useState(false);
  const list = useQuery(catalogListOptions({ query: { q: q || undefined, keyless: keyless || undefined } }));

  return (
    <div className="grid gap-6">
      <div className="grid gap-1.5">
        <Text as="h1" variant="heading2">
          Catalog
        </Text>
        <Text>Pre-built adapters. Install one to create a connector with its tools.</Text>
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
          {list.data ? `${list.data.count} adapters` : list.isPending ? "Loading…" : "Failed to load"}
        </Text>
      </div>
      <ul className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
        {list.data?.adapters.map((a) => (
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
