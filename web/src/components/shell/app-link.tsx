import { forwardRef } from "react";
import { Link } from "@tanstack/react-router";
import type { LinkComponentProps } from "@cloudflare/kumo";

/** An address with a scheme (https:, mailto:) or a protocol-relative one. */
const external = /^([a-z][a-z0-9+.-]*:|\/\/)/i;

/**
 * What Kumo renders for a link. Addresses inside the console go through the
 * router, so moving between screens neither reloads the page nor drops the
 * query cache; anything else is a plain anchor.
 *
 * The root address is only active on itself: every path starts with "/",
 * so a prefix match there would mark the overview current on every screen.
 */
export const AppLink = forwardRef<HTMLAnchorElement, LinkComponentProps>(function AppLink(
  // `to` is Kumo's deprecated alias of `href`; it is dropped, not forwarded.
  { href = "", to: _to, children, ...rest },
  ref,
) {
  if (external.test(href))
    return (
      <a ref={ref} href={href} {...rest}>
        {children}
      </a>
    );
  return (
    <Link ref={ref} to={href} activeOptions={{ exact: href === "/" }} {...rest}>
      {children}
    </Link>
  );
});
